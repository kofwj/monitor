//! Telegram alerts.
//!
//! One pass every [`TICK`] reads every node and every rule, compares what it finds
//! against what the previous pass recorded in `alert_state`, and sends one message
//! for whatever changed.
//!
//! What changed, rather than what is. A rule that is over its threshold is over it
//! on every pass, and a hub that announced that would send the same message every
//! thirty seconds until somebody muted the bot -- which is how an alerting feature
//! ends up switched off. The row in `alert_state` is what makes "changed" mean
//! "changed since last time" across a restart, and its `notified` column is what
//! makes an undelivered message survive to the next pass instead of being lost to
//! one failed HTTP request.
//!
//! Every rule is a small state machine over one node, so the decision and the
//! wording are plain functions over values: no clock, no socket, no hub. The loop
//! at the bottom only gathers, records and sends.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use anyhow::{anyhow, Result};
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use chrono::{Local, NaiveDate, TimeZone, Utc};
use serde_json::{json, Value};
use tracing::{info, warn};

use crate::agent_ws::Agent;
use crate::api::Admin;
use crate::db::{AlertState, Node, Traffic};
use crate::{App, Shared};

/// How often every rule is evaluated.
///
/// The shortest threshold worth configuring is a minute, so half a minute is the
/// resolution that makes it mean what it says: a node that went quiet just after
/// a pass is announced within one of these.
const TICK: Duration = Duration::from_secs(30);

/// What one message may weigh. Telegram's own ceiling is 4096 characters; this
/// leaves room for the markup, and is counted in bytes, which is a little more
/// than the characters it is really limited by -- a message that is split early is
/// cheaper than one that is refused.
const BUDGET: usize = 3_800;

/// Where the Bot API lives. A parameter of [`send`] rather than spliced into the
/// format string there, so a test can point the transport at a local server while
/// [`endpoint`] still proves the address this build actually uses.
const TELEGRAM_API: &str = "https://api.telegram.org";

/// Every key the alert page writes, in the order the panel shows them.
///
/// Test-only, because production reads each key by name where it is used. This
/// list exists so that a test can assert the settings route accepts all of them
/// and hands back all but the token: the two are edited in different files, and
/// either way they can disagree is silent -- a field that can be typed into and
/// never saved, or one that reloads blank however many times it is saved.
#[cfg(test)]
pub const SETTINGS: [&str; 7] = [
    "alert_telegram_token",
    "alert_telegram_chat",
    "alert_offline_minutes",
    "alert_traffic_percent",
    "alert_expiry_days",
    "alert_resource_percent",
    "alert_resource_minutes",
];

// ---- what the panel may write ----

/// A bot token as BotFather issues them: the bot's id, a colon, and the secret.
///
/// Checked because nothing but Telegram ever sees this value, and a token with a
/// character missing from the middle fails as a bare 404 from an endpoint that
/// does not name the setting responsible.
pub fn token_ok(value: &str) -> bool {
    let Some((id, secret)) = value.split_once(':') else { return false };
    id.parse::<u64>().is_ok_and(|n| n > 0)
        && secret.len() >= 30
        && secret.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

/// A chat id: a number, negative for a group, or `@name` for a public channel.
/// Checked for the same reason as the token -- a chat the bot has never been
/// added to is a 400 from Telegram and nothing in the hub's own log.
pub fn chat_ok(value: &str) -> bool {
    match value.strip_prefix('@') {
        Some(name) => !name.is_empty() && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_'),
        None => value.parse::<i64>().is_ok(),
    }
}

// ---- the rules ----

/// The rules as the last pass read them.
#[derive(Debug, Clone, PartialEq)]
pub struct Rules {
    token: String,
    chat: String,
    offline_minutes: i64,
    traffic_percent: i64,
    expiry_days: i64,
    resource_percent: i64,
    resource_minutes: i64,
}

impl Rules {
    pub fn read(app: &App) -> Self {
        let number = |key: &str| app.db.get(key).and_then(|v| v.trim().parse().ok()).unwrap_or(0);
        Self {
            token: app.db.get("alert_telegram_token").unwrap_or_default().trim().to_owned(),
            chat: app.db.get("alert_telegram_chat").unwrap_or_default().trim().to_owned(),
            offline_minutes: number("alert_offline_minutes"),
            traffic_percent: number("alert_traffic_percent"),
            expiry_days: number("alert_expiry_days"),
            resource_percent: number("alert_resource_percent"),
            resource_minutes: number("alert_resource_minutes"),
        }
    }

    /// Whether there is anywhere to send to. A rule switched on without one is
    /// not evaluated: there is no point recording what an operator was told when
    /// there is no way to tell them, and the first pass after a bot is configured
    /// should announce what is true then.
    fn addressed(&self) -> bool {
        !self.token.is_empty() && !self.chat.is_empty()
    }

    /// Which rules are switched on. A threshold of zero is off, the same way a
    /// node with a traffic limit of zero has no limit.
    fn switched_on(&self) -> [(&'static str, bool); 6] {
        let resource = self.resource_percent > 0;
        [
            ("offline", self.offline_minutes > 0),
            ("traffic", self.traffic_percent > 0),
            ("expiry", self.expiry_days > 0),
            ("cpu", resource),
            ("mem", resource),
            ("disk", resource),
        ]
    }
}

/// Everything one pass reads once and every rule then needs.
struct Pass<'a> {
    rules: &'a Rules,
    /// What the previous pass recorded, keyed by node and kind. The resource
    /// rules read it to tell a threshold that has just been crossed from one that
    /// has been crossed for the minutes the operator asked for.
    states: &'a HashMap<(i64, String), AlertState>,
    /// The wall clock, read once so every rule in a pass agrees on it.
    now: i64,
    /// The hub's local date, for the one rule that counts days.
    today: NaiveDate,
    /// How long this hub has been running. Only the offline rule reads it; see
    /// [`Pass::offline`].
    uptime: Duration,
}

impl Pass<'_> {
    fn stored(&self, node: i64, kind: &str) -> Option<&AlertState> {
        self.states.get(&(node, kind.to_owned()))
    }

    /// Everything the rules have to say about one node, in a fixed order.
    ///
    /// One method rather than a registry: the kinds are a closed set, each reads
    /// different data, and a table of them would be a table of closures taking the
    /// union of all their arguments.
    fn judge(&self, node: &Node, live: Option<&Agent>, traffic: &Traffic) -> Vec<Finding> {
        let metrics = live.map(|a| &a.metrics).filter(|m| m.is_object());
        [
            self.offline(node, live.is_some()),
            self.traffic(node, traffic),
            self.expiry(node),
            self.resource(node, metrics, "cpu"),
            self.resource(node, metrics, "mem"),
            self.resource(node, metrics, "disk"),
        ]
        .into_iter()
        .flatten()
        .map(|f| f.named(node))
        .collect()
    }

    /// Whether a node is connected, and for how long it has not been.
    ///
    /// Offline is the absence of a live connection, and how long it has been
    /// absent is `last_seen`, which outlives the process and survives the gap
    /// between a disconnect and the next pass.
    ///
    /// The hub's own uptime guards the first pass. A restart empties the map of
    /// agents, and every node is briefly absent while its agent reconnects; a hub
    /// that had been down for an hour would otherwise announce every node it has
    /// as having been down for an hour, all of them untrue within seconds. Waiting
    /// one threshold means nothing is called offline that has had as long as the
    /// threshold to come back.
    fn offline(&self, node: &Node, connected: bool) -> Verdict {
        let rules = self.rules;
        if rules.offline_minutes <= 0 {
            return None;
        }
        let threshold = rules.offline_minutes * 60;
        if self.uptime < Duration::from_secs(threshold.max(0) as u64) {
            return None;
        }
        let silent = self.now.saturating_sub(node.last_seen);
        if connected || node.last_seen == 0 || silent < threshold {
            return Some(Finding::quiet("offline"));
        }
        Some(Finding::raise("offline", "offline", format!("🔴 已离线 {}", human(silent))))
    }

    /// This period's usage against the node's quota.
    ///
    /// Two states out of one threshold: `warn` where the operator asked to hear,
    /// and `over` at the quota itself, which is worth saying whatever the
    /// threshold is. Setting the threshold to 100 asks for the second alone.
    fn traffic(&self, node: &Node, traffic: &Traffic) -> Verdict {
        if self.rules.traffic_percent <= 0 {
            return None;
        }
        if node.traffic_limit <= 0 {
            // No quota to exceed. A real answer rather than silence, so that a
            // limit removed while a node was over it clears the alarm.
            return Some(Finding::quiet("traffic"));
        }
        let used = usage(node, traffic);
        // Integer, and rounded down: a node at 79.6% of an 80% threshold has not
        // passed it, and the panel draws the same rounded figure beside it.
        let percent = used.saturating_mul(100) / node.traffic_limit;
        let state = match percent {
            p if p >= 100 => "over",
            p if p >= self.rules.traffic_percent => "warn",
            _ => return Some(Finding::quiet("traffic")),
        };
        let spent = format!("{} / {}", bytes(used), bytes(node.traffic_limit));
        let line = match state {
            "over" => format!("🔴 本月流量已用尽 {spent}（{percent}%）"),
            _ => format!("🟠 本月流量 {spent}（{percent}%）"),
        };
        Some(Finding::raise("traffic", state, line))
    }

    /// How long until the node's expiry date.
    ///
    /// The one rule that repeats: a date three days away is still three days away
    /// tomorrow, and the operator has not necessarily acted. [`record`] re-sends
    /// it once a local day while the state holds.
    fn expiry(&self, node: &Node) -> Verdict {
        if self.rules.expiry_days <= 0 {
            return None;
        }
        let Some(expires) = node.expires_at.as_deref().and_then(|d| d.parse::<NaiveDate>().ok()) else {
            // No date, or one the panel would not have stored. Nothing to count
            // down to -- and a node whose date was cleared while it was near
            // expiry has to stop being announced.
            return Some(Finding::quiet("expiry"));
        };
        let days = (expires - self.today).num_days();
        if days > self.rules.expiry_days {
            return Some(Finding::quiet("expiry"));
        }
        let when = match days {
            d if d < 0 => format!("已于 {expires} 到期（{} 天前）", -d),
            0 => format!("今天到期（{expires}）"),
            d => format!("{d} 天后到期（{expires}）"),
        };
        Some(Finding::raise("expiry", "soon", format!("🔵 {when}")))
    }

    /// A live reading against the operator's threshold, once it has held for
    /// `alert_resource_minutes`.
    ///
    /// Two states, because crossing a threshold for a moment is not news and the
    /// minutes in between are the whole point of the setting: `high` while it is
    /// over but not yet long enough, `over` once it has been. Only `over` is
    /// announced; see [`announces`].
    fn resource(&self, node: &Node, metrics: Option<&Value>, kind: &'static str) -> Verdict {
        let rules = self.rules;
        if rules.resource_percent <= 0 {
            return None;
        }
        // A node that is not reporting has no reading, and no reading is not a
        // threshold crossed: the state is cleared, so a reconnect measures the
        // minutes again rather than counting the silence towards them.
        let Some(percent) = metrics.and_then(|m| reading(node, m, kind)) else {
            return Some(Finding::quiet(kind));
        };
        if percent < rules.resource_percent as f64 {
            return Some(Finding::quiet(kind));
        }
        let held = rules.resource_minutes <= 0
            || self.stored(node.id, kind).is_some_and(|s| {
                s.state == "high" && self.now.saturating_sub(s.since) >= rules.resource_minutes * 60
            });
        if !held {
            return Some(Finding { state: "high", line: String::new(), ..Finding::quiet(kind) });
        }
        let name = match kind {
            "cpu" => "CPU",
            "mem" => "内存",
            _ => "硬盘",
        };
        let held_for = match rules.resource_minutes {
            0 => String::new(),
            m => format!("（持续 {m} 分钟）"),
        };
        Some(Finding::raise(kind, "over", format!("🟡 {name} {percent:.0}%{held_for}")))
    }
}

/// Usage counted as the plan bills it, matching `monthUsage` in the panel: a node
/// billed on upload alone measured as the sum of both directions would be compared
/// against the wrong figure.
fn usage(node: &Node, traffic: &Traffic) -> i64 {
    match node.traffic_mode.as_str() {
        "up" => traffic.month_tx,
        "down" => traffic.month_rx,
        "max" => traffic.month_rx.max(traffic.month_tx),
        _ => traffic.month_rx.saturating_add(traffic.month_tx),
    }
}

/// One reading as a percentage of its capacity.
///
/// The capacities come from the report rather than from the stored node, for the
/// reason `api::node_view` gives: a machine that gained a disk while the agent was
/// running has a stored figure that is stale until the next reconnect.
fn reading(node: &Node, metrics: &Value, kind: &str) -> Option<f64> {
    let get = |key: &str| metrics.get(key).and_then(Value::as_f64);
    match kind {
        // Already a percentage: the agent divides by the core count itself.
        "cpu" => get("cpu").filter(|p| p.is_finite()),
        "mem" => share(get("mem_used")?, get("mem_total").unwrap_or(node.mem_total as f64)),
        _ => share(get("disk_used")?, get("disk_total").unwrap_or(node.disk_total as f64)),
    }
}

/// `used` as a percentage of `total`, or nothing where there is no capacity to
/// divide by: a machine reporting no disk is not a machine at 0% of one.
fn share(used: f64, total: f64) -> Option<f64> {
    (total > 0.0).then(|| used / total * 100.0)
}

// ---- one rule's answer ----

/// One rule's answer about one node.
struct Finding {
    /// Set by [`Finding::named`] on the way out of [`Pass::judge`], which is the
    /// only place that knows which node a rule was asked about.
    node: i64,
    /// How the node is named in a message. Carried rather than looked up when the
    /// line is worded, so that wording a row costs no query.
    label: String,
    kind: &'static str,
    /// What this pass puts in `alert_state`, empty when there is nothing to
    /// report. Compared against the stored value to tell a change from a repeat.
    state: &'static str,
    /// The line to send when this state is being entered. A rule going quiet
    /// leaves this unused: the stored row knows how long the state lasted, and
    /// [`clear_line`] is what says so.
    line: String,
}

impl Finding {
    /// The rule has nothing to report, and this is what it records.
    fn quiet(kind: &'static str) -> Self {
        Self { node: 0, label: String::new(), kind, state: "", line: String::new() }
    }

    fn raise(kind: &'static str, state: &'static str, line: String) -> Self {
        Self { state, line, ..Self::quiet(kind) }
    }

    fn named(mut self, node: &Node) -> Self {
        self.node = node.id;
        self.label = label(node);
        if !self.state.is_empty() {
            self.line = format!("{} {}", self.label, self.line);
        }
        self
    }
}

/// Whether a rule is in the state the row records, from a rule that has an
/// opinion. `None` is the rule saying nothing this pass -- switched off, or held
/// back by a guard -- which leaves the row alone rather than reading as a
/// recovery.
type Verdict = Option<Finding>;

/// Whether entering a state is worth a message.
///
/// The resource rules pass through `high` on their way to `over`: a threshold
/// crossed for a moment is not news, and the minutes in between are the whole
/// point of the setting. Leaving a state is the other half of the question; see
/// [`clears`].
fn announces(kind: &str, state: &str) -> bool {
    match state {
        "" => clears(kind),
        "high" => false,
        _ => true,
    }
}

/// Whether leaving a kind's state is worth a message.
///
/// Availability is: an operator told a node went down is owed the fact that it
/// came back, and it is the one thing here they cannot read off a dashboard they
/// are no longer looking at. Quota, expiry and load are not -- the figure crossing
/// back under its threshold is the operator's own doing, and the next billing
/// period starts quiet by itself.
fn clears(kind: &str) -> bool {
    kind == "offline"
}

/// Whether a kind says the same thing again once a local day while it holds.
fn repeats_daily(kind: &str) -> bool {
    kind == "expiry"
}

// ---- the loop ----

/// Evaluates every rule every [`TICK`] and sends whatever changed.
pub async fn run(app: Shared) {
    let started = Instant::now();
    let mut ticker = tokio::time::interval(TICK);
    loop {
        ticker.tick().await;
        let rules = Rules::read(&app);
        if let Err(e) = once(&app, TELEGRAM_API, &rules, started.elapsed()).await {
            warn!("the alert pass failed: {e:#}");
        }
    }
}

/// One pass: gather, record, send.
///
/// `api` is where a message is posted; see [`TELEGRAM_API`].
async fn once(app: &App, api: &str, rules: &Rules, uptime: Duration) -> Result<()> {
    if !rules.addressed() {
        // A hub with nowhere to send has nothing to remember: these rows record
        // what the operator was told, and none of it was. Forgetting them here is
        // also what makes configuring a bot announce the conditions that already
        // hold -- nodes down, quotas passed -- instead of waiting for each of them
        // to happen a second time.
        app.db.forget_alerts(None)?;
        return Ok(());
    }
    // The same for a rule switched off on its own: switched back on, it reports
    // the state of the world rather than the state it was left holding.
    for (kind, on) in rules.switched_on() {
        if !on {
            app.db.forget_alerts(Some(kind))?;
        }
    }

    let pass = Pass {
        rules,
        states: &app.db.alert_states()?,
        now: Utc::now().timestamp(),
        today: Local::now().date_naive(),
        uptime,
    };

    let nodes = app.db.nodes()?;
    let traffic = app.db.all_traffic();
    // Every node, every rule, one pass over the map of connected agents. Held only
    // for the gather: the writes below and the request after them belong to no
    // lock.
    let findings = {
        let agents = app.agents.read().unwrap_or_else(|e| e.into_inner());
        let none = Traffic::default();
        nodes
            .iter()
            .flat_map(|node| pass.judge(node, agents.get(&node.id), traffic.get(&node.id).unwrap_or(&none)))
            .collect()
    };

    let owed = record(app, pass.states, findings, pass.now)?;
    if owed.is_empty() {
        return Ok(());
    }
    deliver(app, api, rules, &owed).await
}

/// Writes what this pass decided, and returns the lines that still owe the
/// operator a message.
///
/// The two are one function because they are one decision: whether a state is news
/// is the transition out of the stored row, and the row is what the write puts
/// there.
fn record(
    app: &App,
    states: &HashMap<(i64, String), AlertState>,
    findings: Vec<Finding>,
    now: i64,
) -> Result<Vec<Finding>> {
    let mut owed = Vec::new();
    for finding in findings {
        let stored = states.get(&(finding.node, finding.kind.to_owned()));
        let previous = stored.map(|s| s.state.as_str()).unwrap_or("");
        let changed = previous != finding.state;
        if stored.is_none() && finding.state.is_empty() {
            // Nothing to report and nothing on record. Writing a row per node per
            // rule to say so would put one in the table for every node that has
            // never alarmed, which is nearly all of them.
            continue;
        }
        let send = if changed {
            announces(finding.kind, finding.state)
        } else {
            match stored {
                // An earlier pass decided this and did not get it away. Retried
                // rather than dropped: this column is the only record that it is
                // owed.
                Some(s) if s.notified == 0 => announces(finding.kind, finding.state),
                // Said once and still true. Expiry is the exception, for the same
                // reason a renewal notice is not sent once a year.
                Some(s) => {
                    repeats_daily(finding.kind)
                        && announces(finding.kind, finding.state)
                        && told_before_today(s, now)
                }
                None => false,
            }
        };
        // Kept across a repeat and across a retry: the duration in the message is
        // the time in the state, not the time since the last attempt.
        let since = match stored {
            Some(s) if !changed => s.since,
            _ => now,
        };
        app.db.set_alert_state(
            finding.node,
            finding.kind,
            finding.state,
            since,
            if send { 0 } else { now },
        )?;
        if send {
            let line = match finding.state.is_empty() {
                true => clear_line(&finding, stored, now),
                false => finding.line.clone(),
            };
            owed.push(Finding { line, ..finding });
        }
    }
    Ok(owed)
}

/// Whether the last message about this row went out on an earlier local day.
fn told_before_today(stored: &AlertState, now: i64) -> bool {
    let day = |ts: i64| Local.timestamp_opt(ts, 0).single().map(|t| t.date_naive());
    match (day(stored.notified), day(now)) {
        (Some(told), Some(today)) => told < today,
        _ => false,
    }
}

/// What to say when a rule goes quiet, from the row that knows how long the state
/// lasted. Only [`clears`] reaches here, so there is one kind to word.
fn clear_line(finding: &Finding, stored: Option<&AlertState>, now: i64) -> String {
    match stored.map(|s| human(now.saturating_sub(s.since))) {
        Some(away) => format!("🟢 {} 已恢复（离线 {away}）", finding.label),
        None => format!("🟢 {} 已恢复", finding.label),
    }
}

/// Sends what is owed, then marks it told.
///
/// The order is the point: a message that failed to send leaves its row owed, so
/// the next pass sends it again rather than the alert being lost to one
/// unreachable minute. A pass that produced several messages and failed on a later
/// one repeats the earlier ones; that is the price of not being able to tell a
/// delivered message from a lost one, and it is cheaper than silence.
async fn deliver(app: &App, api: &str, rules: &Rules, owed: &[Finding]) -> Result<()> {
    for message in render(owed) {
        send(&app.http, api, rules, &message).await?;
    }
    for finding in owed {
        app.db.alert_notified(finding.node, finding.kind, Utc::now().timestamp())?;
    }
    info!("sent {} alert line(s) to the configured chat", owed.len());
    Ok(())
}

/// The address one message goes to.
fn endpoint(api: &str, token: &str) -> String {
    format!("{api}/bot{token}/sendMessage")
}

/// Posts one message.
///
/// The error from a failed request is rebuilt without its URL, because the URL
/// carries the bot token and this error is logged: a hub whose DNS was briefly
/// unreachable would otherwise write its own credential into its journal.
async fn send(client: &reqwest::Client, api: &str, rules: &Rules, text: &str) -> Result<()> {
    let body = json!({
        "chat_id": rules.chat,
        "text": text,
        "parse_mode": "HTML",
        // A node's name is the operator's own text, and one that happens to look
        // like a URL would otherwise unfurl into a card in the chat.
        "link_preview_options": {"is_disabled": true},
    });
    let response = client
        .post(endpoint(api, &rules.token))
        .json(&body)
        .send()
        .await
        .map_err(|e| anyhow!("the telegram request failed: {}", e.without_url()))?;
    let status = response.status();
    if !status.is_success() {
        // Telegram's own words: "chat not found" and "Unauthorized" name the two
        // settings that are wrong, and neither reaches the hub's log otherwise.
        let detail = response.text().await.unwrap_or_default();
        anyhow::bail!("telegram refused the message ({status}): {}", truncate(&detail, 300));
    }
    Ok(())
}

/// The pass as one message, or as several when it has more to say than Telegram
/// will take.
///
/// Grouped by heading so that a node going down and a quota being passed are not
/// interleaved, and ordered so the thing an operator acts on first is at the top.
/// A group that outgrows one message continues into the next under a repeated
/// heading rather than being sent oversized, which Telegram would refuse and the
/// hub would then retry forever.
fn render(owed: &[Finding]) -> Vec<String> {
    let mut ordered: Vec<(u8, &'static str, &str)> = owed
        .iter()
        .map(|f| {
            let (heading, rank) = heading(f.kind, f.state);
            (rank, heading, f.line.as_str())
        })
        .collect();
    // Stable, so nodes keep the order the database gave them within a group.
    ordered.sort_by_key(|(rank, _, _)| *rank);

    let mut messages: Vec<String> = Vec::new();
    let mut current = String::new();
    let mut open = "";
    for (_, heading, line) in ordered {
        let extra = if heading == open { 0 } else { heading.len() + 10 };
        if !current.is_empty() && current.len() + line.len() + extra > BUDGET {
            messages.push(std::mem::take(&mut current));
            open = "";
        }
        if heading != open {
            if !current.is_empty() {
                current.push('\n');
            }
            current.push_str("<b>");
            current.push_str(heading);
            current.push_str("</b>\n");
            open = heading;
        }
        current.push_str(line);
        current.push('\n');
    }
    if !current.is_empty() {
        messages.push(current);
    }
    messages
}

/// A group's heading, and where it sits in the message. Offline first: it is the
/// one an operator acts on immediately.
fn heading(kind: &str, state: &str) -> (&'static str, u8) {
    match (kind, state) {
        ("offline", "offline") => ("离线", 0),
        ("offline", _) => ("已恢复", 1),
        ("traffic", "over") => ("流量用尽", 2),
        ("traffic", _) => ("流量告警", 3),
        ("expiry", _) => ("即将到期", 4),
        ("cpu", _) => ("CPU 占用", 5),
        ("mem", _) => ("内存占用", 6),
        ("disk", _) => ("硬盘占用", 7),
        _ => ("告警", 8),
    }
}

// ---- wording ----

/// Telegram's HTML parse mode reads exactly three characters as markup, and a
/// node's name is whatever the operator typed. Escaped for the same reason the
/// panel renders it as text rather than markup.
fn escape(text: &str) -> String {
    text.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;")
}

/// How a node is named in a message: its name, and the country it sits in when the
/// hub knows one. Two nodes may share a name, and a message naming only the name
/// would leave the operator to guess which machine went down.
fn label(node: &Node) -> String {
    let name = escape(&node.name);
    match node.country.is_empty() {
        true => name,
        false => format!("{name}（{}）", escape(&node.country)),
    }
}

/// A duration as a message says it: the two largest units. "1 天 4 小时 12 分钟
/// 8 秒" is not more useful than "1 天 4 小时", and it is harder to read at a
/// glance, which is the only way these are read.
fn human(seconds: i64) -> String {
    let (d, h, m) = (seconds / 86_400, seconds % 86_400 / 3_600, seconds % 3_600 / 60);
    match (d, h, m) {
        (d, h, _) if d > 0 && h > 0 => format!("{d} 天 {h} 小时"),
        (d, _, _) if d > 0 => format!("{d} 天"),
        (_, h, m) if h > 0 && m > 0 => format!("{h} 小时 {m} 分钟"),
        (_, h, _) if h > 0 => format!("{h} 小时"),
        (_, _, m) if m > 0 => format!("{m} 分钟"),
        _ => format!("{seconds} 秒"),
    }
}

/// Bytes as the panel writes them: 1024-based, three significant digits, labelled
/// the way `df -h` labels them. Kept in step with `bytes` in `lib/format.ts`.
fn bytes(n: i64) -> String {
    const UNITS: [&str; 6] = ["B", "KB", "MB", "GB", "TB", "PB"];
    if n < 1 {
        return "0 B".into();
    }
    let mut index = 0;
    let mut value = n as f64;
    while value >= 1024.0 && index < UNITS.len() - 1 {
        value /= 1024.0;
        index += 1;
    }
    let digits = match index == 0 || value >= 100.0 {
        true => 0,
        false => match value >= 10.0 {
            true => 1,
            false => 2,
        },
    };
    format!("{value:.digits$} {}", UNITS[index])
}

fn truncate(text: &str, limit: usize) -> String {
    match text.char_indices().nth(limit) {
        Some((at, _)) => format!("{}…", &text[..at]),
        None => text.to_owned(),
    }
}

// ---- the panel ----

/// Sends one message with the stored configuration.
///
/// The way to find out that a token is wrong is here, while an operator is looking
/// at the page, rather than the first time a node goes down. Deliberately not a
/// GET: it puts a message in a chat, and a GET is something a browser, a link
/// preview or a proxy may issue on its own.
pub async fn test(_: Admin, State(app): State<Shared>) -> Response {
    let rules = Rules::read(&app);
    if !rules.addressed() {
        return (StatusCode::BAD_REQUEST, "先填写 Bot Token 和 Chat ID").into_response();
    }
    let text = "🟢 monitor-hub 测试消息\n收到这条说明告警已经接通。";
    match send(&app.http, TELEGRAM_API, &rules, text).await {
        Ok(()) => Json(json!({"ok": true})).into_response(),
        // Telegram's refusal, not a generic one: it is the only thing that says
        // which of the two settings is wrong.
        Err(e) => (StatusCode::BAD_GATEWAY, format!("{e:#}")).into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::Db;
    use chrono::Duration as Span;
    use std::sync::{Arc, Mutex};

    fn node(name: &str) -> Node {
        Node { id: 1, name: name.into(), traffic_reset_day: 1, ..Default::default() }
    }

    fn rules() -> Rules {
        Rules {
            token: "1:abcdefghijklmnopqrstuvwxyz0123456789".into(),
            chat: "-100123".into(),
            offline_minutes: 5,
            traffic_percent: 80,
            expiry_days: 7,
            resource_percent: 90,
            resource_minutes: 5,
        }
    }

    /// A pass over one node, which is what every rule test needs.
    fn pass<'a>(rules: &'a Rules, states: &'a HashMap<(i64, String), AlertState>, now: i64) -> Pass<'a> {
        Pass {
            rules,
            states,
            now,
            today: NaiveDate::from_ymd_opt(2026, 9, 15).unwrap(),
            uptime: Duration::from_secs(3_600),
        }
    }

    fn none() -> HashMap<(i64, String), AlertState> {
        HashMap::new()
    }

    /// A hub with one node. `alert_state` carries a foreign key to `node`, and a
    /// row for a node that does not exist is what it is there to prevent.
    fn hub() -> (App, i64) {
        let app = App::for_test(Db::open(":memory:").unwrap());
        let id = app.db.create_node(&node("web"), "token").unwrap();
        (app, id)
    }

    /// A line to send about `node`, as `record` takes one.
    fn line(node: i64, kind: &'static str, state: &'static str) -> Finding {
        Finding { node, label: "web".into(), kind, state, line: format!("line {state}") }
    }

    fn holding(kind: &str, state: &str, since: i64) -> HashMap<(i64, String), AlertState> {
        let mut map = HashMap::new();
        map.insert((1, kind.to_owned()), AlertState { state: state.into(), since, notified: 0 });
        map
    }

    /// Each field is read from the key its name says, and a distinct value in each
    /// is what proves it: a key renamed in one of the two places -- here and the
    /// panel -- leaves a rule silently switched off, and a value of zero is what
    /// that looks like.
    #[test]
    fn every_rule_reads_the_key_it_is_named_after() {
        let app = App::for_test(Db::open(":memory:").unwrap());
        let stored = [
            ("alert_telegram_token", "123456789:AAHdqTcvCH1vGWJxfSeofSAs0K5PALDsaw"),
            ("alert_telegram_chat", "-1001234567890"),
            ("alert_offline_minutes", "11"),
            ("alert_traffic_percent", "22"),
            ("alert_expiry_days", "33"),
            ("alert_resource_percent", "44"),
            ("alert_resource_minutes", "55"),
        ];
        for (key, value) in stored {
            assert!(SETTINGS.contains(&key), "{key} is read but not listed as a setting");
            app.db.set(key, value).unwrap();
        }

        let rules = Rules::read(&app);
        assert_eq!(rules.token, stored[0].1);
        assert_eq!(rules.chat, stored[1].1);
        assert_eq!(rules.offline_minutes, 11);
        assert_eq!(rules.traffic_percent, 22);
        assert_eq!(rules.expiry_days, 33);
        assert_eq!(rules.resource_percent, 44);
        assert_eq!(rules.resource_minutes, 55);

        // Nothing stored reads as every rule off, which is the default a hub that
        // has never opened the page must have.
        let fresh = Rules::read(&App::for_test(Db::open(":memory:").unwrap()));
        assert_eq!(fresh.switched_on().iter().filter(|(_, on)| *on).count(), 0);
        assert!(!fresh.addressed());
    }

    #[test]
    fn a_token_is_only_accepted_in_the_shape_botfather_issues() {
        assert!(token_ok("123456789:AAHdqTcvCH1vGWJxfSeofSAs0K5PALDsaw"));
        // A truncated paste, which is what this exists for: the id and colon are
        // there and the secret is half of one.
        assert!(!token_ok("123456789:AAHdqTcvCH1vGWJxfSeo"));
        assert!(!token_ok("123456789"));
        assert!(!token_ok(":AAHdqTcvCH1vGWJxfSeofSAs0K5PALDsaw"));
        assert!(!token_ok("notanid:AAHdqTcvCH1vGWJxfSeofSAs0K5PALDsaw"));
        // A space is what a copy out of a chat window brings with it.
        assert!(!token_ok("123456789:AAHdqTcvCH1vGWJxfSeofSAs0K5PALDsaw "));
    }

    #[test]
    fn a_chat_id_is_a_number_a_group_or_a_public_channel() {
        assert!(chat_ok("-1001234567890"));
        assert!(chat_ok("123456"));
        assert!(chat_ok("@monitor_alerts"));
        assert!(!chat_ok("@"));
        assert!(!chat_ok("monitor_alerts"));
        assert!(!chat_ok("12 34"));
    }

    /// The threshold is in minutes and `last_seen` advances once a minute, so a
    /// node is not offline until it has been quiet for the whole of it.
    #[test]
    fn a_node_is_offline_once_it_has_been_quiet_for_the_threshold() {
        let now = 1_700_000_000;
        let rules = rules();
        let empty = none();
        let p = pass(&rules, &empty, now);

        let mut n = node("web");
        n.last_seen = now - 4 * 60;
        assert_eq!(p.offline(&n, false).unwrap().state, "", "four minutes of five");

        n.last_seen = now - 5 * 60;
        let found = p.offline(&n, false).unwrap();
        assert_eq!(found.state, "offline");
        assert_eq!(found.line, "🔴 已离线 5 分钟");

        // Connected, whatever `last_seen` says: the map of agents is the fact.
        assert_eq!(p.offline(&n, true).unwrap().state, "");

        // A node that has never reported has no silence to measure.
        assert_eq!(p.offline(&node("new"), false).unwrap().state, "");

        // A rule that is off says nothing at all, which is not the same as saying
        // the node is fine: the row is left as it was.
        let off = Rules { offline_minutes: 0, ..rules.clone() };
        assert!(pass(&off, &empty, now).offline(&n, false).is_none());
    }

    /// The guard that keeps a restart from announcing every node a hub has.
    #[test]
    fn a_restart_does_not_call_a_node_offline_before_its_agent_can_reconnect() {
        let now = 1_700_000_000;
        let rules = rules();
        let empty = none();
        let mut n = node("web");
        // The hub was down for an hour, so every node's last report is an hour old.
        n.last_seen = now - 3_600;

        let fresh = Pass { uptime: Duration::from_secs(30), ..pass(&rules, &empty, now) };
        assert!(
            fresh.offline(&n, false).is_none(),
            "the first pass must not read the hub's own downtime as the node's"
        );

        let settled = Pass { uptime: Duration::from_secs(600), ..pass(&rules, &empty, now) };
        assert_eq!(
            settled.offline(&n, false).unwrap().state,
            "offline",
            "once the node has had as long as the threshold to come back"
        );
    }

    #[test]
    fn usage_is_counted_the_way_the_plan_bills_it() {
        let traffic = Traffic { month_rx: 100, month_tx: 250, ..Default::default() };
        let mut n = node("web");
        for (mode, want) in [("sum", 350), ("down", 100), ("up", 250), ("max", 250)] {
            n.traffic_mode = mode.into();
            assert_eq!(usage(&n, &traffic), want, "{mode}");
        }
    }

    #[test]
    fn a_quota_is_warned_at_the_threshold_and_called_exhausted_at_the_limit() {
        let rules = rules();
        let empty = none();
        let p = pass(&rules, &empty, 1_700_000_000);
        let mut n = node("web");
        n.traffic_limit = 1_000;

        let mut at = |limit: i64, rx: i64| {
            n.traffic_limit = limit;
            let traffic = Traffic { month_rx: rx, ..Default::default() };
            p.traffic(&n, &traffic).unwrap()
        };
        assert_eq!(at(1_000, 700).state, "");
        assert_eq!(at(1_000, 800).state, "warn");
        assert_eq!(at(1_000, 800).line, "🟠 本月流量 800 B / 1000 B（80%）");
        assert_eq!(at(1_000, 999).state, "warn");
        assert_eq!(at(1_000, 1_000).state, "over");
        assert_eq!(at(1_000, 1_400).state, "over");

        // No quota is not a quota of zero: the state clears rather than alarming.
        assert_eq!(at(0, 1_400).state, "");
        assert_eq!(at(0, 1_400).line, "");
    }

    /// A figure just under the threshold has not crossed it, and the panel draws
    /// the same rounded percentage beside it.
    #[test]
    fn a_percentage_below_the_threshold_does_not_cross_it() {
        let rules = Rules { traffic_percent: 80, ..rules() };
        let empty = none();
        let p = pass(&rules, &empty, 1_700_000_000);
        let mut n = node("web");
        n.traffic_limit = 1_000;
        let traffic = Traffic { month_rx: 799, ..Default::default() };
        assert_eq!(p.traffic(&n, &traffic).unwrap().state, "");
    }

    #[test]
    fn expiry_is_announced_inside_the_window_and_says_which_side_of_today_it_is() {
        let rules = rules();
        let empty = none();
        let p = pass(&rules, &empty, 1_700_000_000);
        let mut n = node("web");

        n.expires_at = Some("2026-09-30".into());
        assert_eq!(p.expiry(&n).unwrap().state, "", "fifteen days out");

        n.expires_at = Some("2026-09-18".into());
        let soon = p.expiry(&n).unwrap();
        assert_eq!(soon.state, "soon");
        assert_eq!(soon.line, "🔵 3 天后到期（2026-09-18）");

        n.expires_at = Some("2026-09-15".into());
        assert!(p.expiry(&n).unwrap().line.contains("今天到期"));

        n.expires_at = Some("2026-09-12".into());
        assert!(p.expiry(&n).unwrap().line.contains("3 天前"), "already past");

        // A date the panel would not have stored, and no date at all.
        n.expires_at = Some("whenever".into());
        assert_eq!(p.expiry(&n).unwrap().state, "");
        n.expires_at = None;
        assert_eq!(p.expiry(&n).unwrap().state, "");
    }

    #[test]
    fn a_reading_is_a_share_of_the_capacity_the_report_carries() {
        let n = Node { mem_total: 1_000, disk_total: 2_000, ..node("web") };
        let m =
            json!({"cpu": 91.5, "mem_used": 500, "mem_total": 4_000, "disk_used": 500, "disk_total": 2_000});
        assert_eq!(reading(&n, &m, "cpu"), Some(91.5));
        assert_eq!(reading(&n, &m, "mem"), Some(12.5), "the report's capacity, not the stored one");
        assert_eq!(reading(&n, &m, "disk"), Some(25.0));

        // A machine reporting no capacity is not one at 0% of it.
        let empty = json!({"cpu": 1.0, "mem_used": 5, "mem_total": 0, "disk_used": 5, "disk_total": 0});
        assert_eq!(reading(&n, &empty, "mem"), None);
        assert_eq!(reading(&n, &empty, "disk"), None);
    }

    /// The minutes are the point of the setting, so a threshold crossed once is
    /// not announced and one that holds is.
    #[test]
    fn a_reading_has_to_hold_before_it_is_announced() {
        let rules = rules();
        let now = 1_700_000_000;
        let empty = none();
        let hot = json!({"cpu": 99.0});

        let first = pass(&rules, &empty, now).resource(&node("web"), Some(&hot), "cpu").unwrap();
        assert_eq!(first.state, "high");
        assert_eq!(first.line, "", "nothing to send while it is only high");
        assert!(!announces("cpu", "high"), "and it stays unsaid");

        // Still high a minute in: not yet five.
        let early = holding("cpu", "high", now - 60);
        assert_eq!(
            pass(&rules, &early, now).resource(&node("web"), Some(&hot), "cpu").unwrap().state,
            "high"
        );

        let held = holding("cpu", "high", now - 300);
        let over = pass(&rules, &held, now).resource(&node("web"), Some(&hot), "cpu").unwrap();
        assert_eq!(over.state, "over");
        assert_eq!(over.line, "🟡 CPU 99%（持续 5 分钟）");

        // Cooled down, and a node that stopped reporting: both clear the state, so
        // a reconnect measures the minutes again rather than counting the silence
        // towards them.
        let cold = json!({"cpu": 10.0});
        assert_eq!(pass(&rules, &held, now).resource(&node("web"), Some(&cold), "cpu").unwrap().state, "");
        assert_eq!(pass(&rules, &held, now).resource(&node("web"), None, "cpu").unwrap().state, "");

        // Zero minutes asks for the first reading that crosses.
        let now_rules = Rules { resource_minutes: 0, ..rules.clone() };
        let immediate = pass(&now_rules, &empty, now).resource(&node("web"), Some(&hot), "cpu").unwrap();
        assert_eq!(immediate.state, "over");
        assert_eq!(immediate.line, "🟡 CPU 99%");
    }

    /// The whole reason for the table: a condition that is still true on the next
    /// pass is not announced again, and one that has changed is.
    #[test]
    fn a_state_is_announced_when_it_changes_and_not_while_it_holds() {
        let (app, id) = hub();
        let now = 1_700_000_000;
        let find = |state: &'static str| line(id, "offline", state);

        let first = record(&app, &none(), vec![find("offline")], now).unwrap();
        assert_eq!(first.len(), 1, "entering the state is news");
        // Told, which is what `deliver` does once the message is away.
        app.db.alert_notified(id, "offline", now).unwrap();

        let states = app.db.alert_states().unwrap();
        assert!(
            record(&app, &states, vec![find("offline")], now + 30).unwrap().is_empty(),
            "still offline is not news"
        );

        // Recovery, which offline does report, with the duration taken from the
        // row rather than from this pass.
        let states = app.db.alert_states().unwrap();
        let back = record(&app, &states, vec![find("")], now + 600).unwrap();
        assert_eq!(back.len(), 1);
        assert_eq!(back[0].line, "🟢 web 已恢复（离线 10 分钟）");
        app.db.alert_notified(id, "offline", now + 600).unwrap();

        // And the quiet that follows is not news either.
        let states = app.db.alert_states().unwrap();
        assert!(record(&app, &states, vec![find("")], now + 630).unwrap().is_empty());
    }

    /// A quota coming back under its threshold is the operator's own doing, and
    /// the next period starts quiet by itself: only availability is reported both
    /// ways.
    #[test]
    fn a_quota_going_back_under_its_threshold_is_not_announced() {
        let (app, id) = hub();
        let now = 1_700_000_000;
        let find = |state: &'static str| line(id, "traffic", state);

        assert_eq!(record(&app, &none(), vec![find("warn")], now).unwrap().len(), 1);
        // Passing the quota is a further change and is worth saying.
        let states = app.db.alert_states().unwrap();
        assert_eq!(record(&app, &states, vec![find("over")], now + 60).unwrap().len(), 1);
        // Dropping back is not.
        let states = app.db.alert_states().unwrap();
        assert!(record(&app, &states, vec![find("")], now + 120).unwrap().is_empty());
        // And it is on record as quiet, so the next period can warn again.
        assert_eq!(app.db.alert_states().unwrap()[&(id, "traffic".to_owned())].state, "");
    }

    /// A message that did not get away is sent on the next pass rather than lost
    /// to one unreachable minute.
    #[test]
    fn a_decision_that_was_not_delivered_is_owed_again() {
        let (app, id) = hub();
        let now = 1_700_000_000;
        let find = || line(id, "offline", "offline");

        // A pass that decided and then failed to send: `record` alone, without the
        // `alert_notified` that follows a delivered message.
        assert_eq!(record(&app, &none(), vec![find()], now).unwrap().len(), 1);
        assert_eq!(app.db.alert_states().unwrap()[&(id, "offline".to_owned())].notified, 0, "not yet told");

        let states = app.db.alert_states().unwrap();
        assert_eq!(record(&app, &states, vec![find()], now + 30).unwrap().len(), 1, "still owed");
        assert_eq!(
            app.db.alert_states().unwrap()[&(id, "offline".to_owned())].since,
            now,
            "the duration does not restart"
        );

        // Told, and then it stops.
        app.db.alert_notified(id, "offline", now + 30).unwrap();
        let states = app.db.alert_states().unwrap();
        assert!(record(&app, &states, vec![find()], now + 60).unwrap().is_empty());
    }

    /// Expiry is the one kind that repeats, because a date three days away is
    /// still three days away tomorrow and nobody has necessarily acted.
    #[test]
    fn an_expiry_is_repeated_once_a_local_day_and_nothing_else_is() {
        let (app, id) = hub();
        let day = Local::now().date_naive();
        let at = |d: NaiveDate, h: u32, m: u32| {
            d.and_hms_opt(h, m, 0).unwrap().and_local_timezone(Local).unwrap().timestamp()
        };
        let find = |kind: &'static str| line(id, kind, "soon");

        let morning = at(day, 0, 30);
        assert_eq!(record(&app, &none(), vec![find("expiry")], morning).unwrap().len(), 1);
        app.db.alert_notified(id, "expiry", morning).unwrap();
        let states = app.db.alert_states().unwrap();
        assert!(
            record(&app, &states, vec![find("expiry")], at(day, 12, 0)).unwrap().is_empty(),
            "the same day"
        );

        let states = app.db.alert_states().unwrap();
        let tomorrow = at(day + Span::days(1), 0, 30);
        assert_eq!(record(&app, &states, vec![find("expiry")], tomorrow).unwrap().len(), 1, "the next day");

        // A kind that is not repeated stays quiet however long it holds.
        assert_eq!(record(&app, &none(), vec![find("traffic")], morning).unwrap().len(), 1);
        app.db.alert_notified(id, "traffic", morning).unwrap();
        let states = app.db.alert_states().unwrap();
        assert!(record(&app, &states, vec![find("traffic")], tomorrow).unwrap().is_empty());
    }

    #[test]
    fn the_message_groups_by_heading_and_puts_offline_first() {
        let owed = vec![
            Finding {
                kind: "expiry",
                state: "soon",
                line: "🔵 db 3 天后到期".into(),
                ..Finding::quiet("expiry")
            },
            Finding {
                kind: "offline",
                state: "offline",
                line: "🔴 web 已离线 5 分钟".into(),
                ..Finding::quiet("offline")
            },
            Finding {
                kind: "offline",
                state: "",
                line: "🟢 api 已恢复（离线 9 分钟）".into(),
                ..Finding::quiet("offline")
            },
            Finding {
                kind: "traffic",
                state: "warn",
                line: "🟠 db 本月流量 80%".into(),
                ..Finding::quiet("traffic")
            },
        ];
        let messages = render(&owed);
        assert_eq!(messages.len(), 1);
        let text = &messages[0];
        assert!(text.starts_with("<b>离线</b>\n"), "{text}");
        let order: Vec<usize> =
            ["离线", "已恢复", "流量告警", "即将到期"].iter().map(|h| text.find(h).unwrap()).collect();
        assert!(order.windows(2).all(|w| w[0] < w[1]), "{text}");
        assert_eq!(text.matches("<b>").count(), 4);
    }

    /// Telegram refuses an oversized message, so a pass with more to say than that
    /// becomes several rather than one the hub retries forever.
    #[test]
    fn a_pass_longer_than_one_message_is_split_and_keeps_its_headings() {
        let owed: Vec<Finding> = (0..400)
            .map(|i| Finding {
                node: i,
                kind: "offline",
                state: "offline",
                line: format!("🔴 node-{i:04} 已离线 5 分钟"),
                ..Finding::quiet("offline")
            })
            .collect();
        let messages = render(&owed);
        assert!(messages.len() > 1, "one message for 400 nodes");
        for message in &messages {
            assert!(message.len() <= BUDGET, "{} characters", message.len());
            assert!(message.contains("<b>离线</b>"), "every message says what it is about");
        }
        // Every line survives the split exactly once.
        assert_eq!(messages.iter().map(|m| m.matches("已离线").count()).sum::<usize>(), 400);
    }

    /// The panel renders node names as text, and so must this: a name is the
    /// operator's own string, and one carrying a bracket would otherwise inject
    /// markup into a message the hub signs.
    #[test]
    fn a_node_name_cannot_inject_markup_into_the_message() {
        assert_eq!(escape("a & b <c>"), "a &amp; b &lt;c&gt;");
        // Ampersand first, or the escapes themselves are escaped twice.
        assert_eq!(escape("<&>"), "&lt;&amp;&gt;");

        let n = Node { name: "<b>x</b>".into(), country: "JP".into(), ..node("x") };
        assert_eq!(label(&n), "&lt;b&gt;x&lt;/b&gt;（JP）");
        // A node with no country is named by its name alone.
        assert_eq!(label(&node("web")), "web");
    }

    #[test]
    fn the_endpoint_is_the_one_this_build_uses() {
        assert_eq!(endpoint(TELEGRAM_API, "123:abc"), "https://api.telegram.org/bot123:abc/sendMessage");
    }

    #[test]
    fn a_duration_reads_as_the_two_largest_units() {
        assert_eq!(human(9), "9 秒");
        assert_eq!(human(60), "1 分钟");
        assert_eq!(human(3_599), "59 分钟");
        assert_eq!(human(3_600), "1 小时");
        assert_eq!(human(3_900), "1 小时 5 分钟");
        assert_eq!(human(86_400), "1 天");
        assert_eq!(human(90_000), "1 天 1 小时");
    }

    #[test]
    fn bytes_read_the_way_the_panel_writes_them() {
        assert_eq!(bytes(0), "0 B");
        assert_eq!(bytes(999), "999 B");
        assert_eq!(bytes(1024), "1.00 KB");
        assert_eq!(bytes(1024 * 1024), "1.00 MB");
        assert_eq!(bytes(1024_i64.pow(3)), "1.00 GB");
        assert_eq!(bytes(10 * 1024_i64.pow(3)), "10.0 GB");
        assert_eq!(bytes(100 * 1024_i64.pow(3)), "100 GB");
    }

    /// A hub with no bot configured must not accumulate a record of things it
    /// never said, or configuring one would announce nothing at all.
    #[tokio::test]
    async fn a_hub_with_no_bot_forgets_rather_than_records() {
        let (app, id) = hub();
        let now = Utc::now().timestamp();
        app.db.set_alert_state(id, "offline", "offline", now, now).unwrap();

        let silent = Rules { token: String::new(), ..rules() };
        once(&app, TELEGRAM_API, &silent, Duration::from_secs(3_600)).await.unwrap();
        assert!(app.db.alert_states().unwrap().is_empty(), "nothing to tell anyone with");

        // A rule switched off on its own forgets its own kind and no other.
        app.db.set_alert_state(id, "offline", "offline", now, now).unwrap();
        app.db.set_alert_state(id, "expiry", "soon", now, now).unwrap();
        let no_offline = Rules { offline_minutes: 0, ..rules() };
        once(&app, TELEGRAM_API, &no_offline, Duration::from_secs(3_600)).await.unwrap();
        let left = app.db.alert_states().unwrap();
        assert!(!left.contains_key(&(id, "offline".to_owned())));
        assert!(left.contains_key(&(id, "expiry".to_owned())));
    }

    /// A stand-in for the Bot API: records the body of every request and answers
    /// with whatever Telegram would.
    async fn mock_telegram(status: StatusCode, answer: &'static str) -> (String, Arc<Mutex<Vec<Value>>>) {
        let seen: Arc<Mutex<Vec<Value>>> = Arc::default();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let sink = seen.clone();
        let router = axum::Router::new().fallback(move |body: String| {
            let sink = sink.clone();
            async move {
                sink.lock().unwrap().push(serde_json::from_str(&body).unwrap_or(Value::Null));
                (status, answer)
            }
        });
        tokio::spawn(async move {
            let _ = axum::serve(listener, router).await;
        });
        (format!("http://{addr}"), seen)
    }

    const TOKEN: &str = "123456789:AAHdqTcvCH1vGWJxfSeofSAs0K5PALDsaw";

    /// A hub with a bot configured, one node that has been quiet for ten minutes,
    /// and a client that ignores the proxy variables this environment sets.
    fn wired() -> (App, i64) {
        let (mut app, id) = hub();
        app.http = reqwest::Client::builder().no_proxy().build().unwrap();
        app.db.set("alert_telegram_token", TOKEN).unwrap();
        app.db.set("alert_telegram_chat", "-100123").unwrap();
        app.db.set("alert_offline_minutes", "5").unwrap();
        let now = Utc::now().timestamp();
        app.db.touch_seen(id, now - 600).unwrap();
        (app, id)
    }

    /// The whole pass against a server standing in for Telegram: what the body
    /// says, and that a condition which has not changed is not said twice.
    #[tokio::test]
    async fn a_pass_reaches_telegram_once_and_the_next_pass_says_nothing() {
        let (api, seen) = mock_telegram(StatusCode::OK, r#"{"ok":true}"#).await;
        let (app, _) = wired();
        let rules = Rules::read(&app);
        assert!(rules.addressed(), "a token and a chat are all that is needed to send");

        once(&app, &api, &rules, Duration::from_secs(3_600)).await.unwrap();

        {
            let sent = seen.lock().unwrap();
            assert_eq!(sent.len(), 1, "one pass, one message");
            let body = &sent[0];
            assert_eq!(body["chat_id"], "-100123");
            assert_eq!(body["parse_mode"], "HTML");
            assert_eq!(body["link_preview_options"]["is_disabled"], true);
            let text = body["text"].as_str().unwrap();
            assert!(text.starts_with("<b>离线</b>\n"), "{text}");
            assert!(text.contains("web"), "{text}");
            assert!(text.contains("已离线 10 分钟"), "{text}");
        }

        // Told once. The node is still down and the operator already knows.
        once(&app, &api, &rules, Duration::from_secs(3_600)).await.unwrap();
        assert_eq!(seen.lock().unwrap().len(), 1, "an unchanged condition is not repeated");
    }

    /// A refusal from Telegram leaves the alert owed rather than dropped, and
    /// neither the message nor the hub's log may carry the credential.
    #[tokio::test]
    async fn a_refused_message_is_owed_again_and_its_error_does_not_carry_the_token() {
        let (api, seen) =
            mock_telegram(StatusCode::UNAUTHORIZED, r#"{"ok":false,"description":"Unauthorized"}"#).await;
        let (app, id) = wired();
        let rules = Rules::read(&app);

        let failure = once(&app, &api, &rules, Duration::from_secs(3_600)).await.unwrap_err().to_string();
        assert!(failure.contains("Unauthorized"), "Telegram's own words name the setting: {failure}");
        assert!(!failure.contains(TOKEN), "the error must not carry the bot token: {failure}");
        assert_eq!(seen.lock().unwrap().len(), 1);

        // Still owed, so the next pass tries again rather than the alert being
        // lost to one bad minute.
        assert_eq!(app.db.alert_states().unwrap()[&(id, "offline".to_owned())].notified, 0);
        assert!(once(&app, &api, &rules, Duration::from_secs(3_600)).await.is_err());
        assert_eq!(seen.lock().unwrap().len(), 2, "tried again");
    }

    /// The token is part of the URL, and a URL is part of the error a failed
    /// request produces -- which this logs. A hub whose DNS was briefly
    /// unreachable must not write its own credential into its journal.
    #[tokio::test]
    async fn a_request_that_never_arrived_does_not_put_the_token_in_the_log() {
        let (app, _) = wired();
        let rules = Rules::read(&app);
        // Port 1 on loopback is reserved and nothing here listens on it.
        let failure = send(&app.http, "http://127.0.0.1:1", &rules, "hello").await.unwrap_err().to_string();
        assert!(failure.contains("telegram request failed"), "{failure}");
        assert!(!failure.contains(TOKEN), "the token is in the URL and must not reach the log: {failure}");
    }
}
