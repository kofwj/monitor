//! Telegram and webhook alerts.
//!
//! One pass every [`TICK`] reads every node and every rule, compares what it finds
//! against what the previous pass recorded in `alert_state`, and sends one message
//! for whatever changed. A hub with both channels configured posts to both; the
//! message is the same one, rendered per channel by [`compose`].
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

use std::collections::{HashMap, HashSet};
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

/// Where the Bot API lives. A parameter of [`send_telegram`] rather than spliced
/// into the format string there, so a test can point the transport at a local
/// server while [`endpoint`] still proves the address this build actually uses.
const TELEGRAM_API: &str = "https://api.telegram.org";

/// What a heading is wrapped in, per channel. Telegram's HTML parse mode reads
/// `<b>` as bold; a webhook's reader is a script, which would show the tags.
const HTML: (&str, &str) = ("<b>", "</b>");
const PLAIN: (&str, &str) = ("", "");

/// Every key the alert page writes, in the order the panel shows them.
///
/// Test-only, because production reads each key by name where it is used. This
/// list exists so that a test can assert the settings route accepts all of them
/// and hands back all but the token: the two are edited in different files, and
/// either way they can disagree is silent -- a field that can be typed into and
/// never saved, or one that reloads blank however many times it is saved.
#[cfg(test)]
pub const SETTINGS: [&str; 10] = [
    "alert_telegram_token",
    "alert_telegram_chat",
    "alert_webhook_url",
    "alert_webhook_headers",
    "alert_offline_minutes",
    "alert_traffic_percent",
    "alert_expiry_days",
    "alert_resource_percent",
    "alert_resource_minutes",
    "alert_muted_nodes",
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

/// A webhook address: a scheme the hub can speak, and a host after it.
///
/// Checked because this URL is posted to on every pass, and a typo fails as a
/// request error in the hub's journal that does not name the setting -- which is
/// the same failure as an endpoint that is down, a thing an operator may be
/// living with on purpose.
///
/// `http://` is allowed where `github_proxy` insists on `https://`. What travels
/// this URL is a sentence about which of the operator's nodes went down, not a
/// binary another machine will execute; the same reason the bot token is worth
/// more than the message it sends.
pub fn webhook_ok(value: &str) -> bool {
    let Some(rest) = value.strip_prefix("https://").or_else(|| value.strip_prefix("http://")) else {
        return false;
    };
    let host = rest.split(['/', '?', '#']).next().unwrap_or("");
    !host.is_empty() && !value.chars().any(|c| c.is_whitespace() || c.is_control())
}

/// The punctuation RFC 9110 allows in a header field name, minus the space.
const HEADER_PUNCT: &str = "!#$%&'*+-.^_`|~";

/// Extra request headers, one `Name: value` per line, empty meaning none.
///
/// The shape every self-hosted endpoint already documents, and the one a `curl`
/// example in its README is written in, rather than a field per header: the hub
/// cannot know whether the operator needs `Authorization`, `X-Gotify-Key`, or
/// nothing at all.
///
/// Checked because the headers are rebuilt on every pass, so a line with no colon
/// would be dropped there in silence -- an endpoint answering 401 to a request
/// that looks, from the panel, fully configured.
pub fn headers_ok(value: &str) -> bool {
    value.lines().filter(|line| !line.trim().is_empty()).all(|line| match line.split_once(':') {
        Some((name, _)) => {
            let name = name.trim();
            !name.is_empty() && name.chars().all(|c| c.is_ascii_alphanumeric() || HEADER_PUNCT.contains(c))
        }
        None => false,
    })
}

/// The nodes to stay quiet about, as the panel writes them: comma-separated ids,
/// empty meaning none.
///
/// Checked because the value is parsed on every pass by [`Rules::read`], where a
/// part that does not parse is skipped in silence -- so a typo would mute a
/// different set of nodes than the panel shows, and nothing would say so. Ids are
/// what is stored rather than names: a node can be renamed, and a mute that
/// followed the name would move to whichever node took it.
pub fn muted_ok(value: &str) -> bool {
    value.is_empty() || value.split(',').all(|part| part.trim().parse::<i64>().is_ok_and(|id| id > 0))
}

/// Drops one node from that list, which is what deleting a node has to do.
///
/// Ids are what is stored, and SQLite hands a deleted node's id to the next one
/// created: an entry left behind therefore mutes a machine nobody muted, and
/// quietly, because the pass never looks at a muted node. Nothing in the list
/// itself can tell the two apart -- the id is the same id -- so the deletion is
/// where it has to be removed. `Rules::read` also drops an id that names no node
/// at all, which is the state a list left by an older build is in until some node
/// takes the id.
pub fn unmute(app: &App, id: i64) -> Result<()> {
    let muted = app.db.get("alert_muted_nodes").unwrap_or_default();
    let ids: Vec<i64> = muted.split(',').filter_map(|part| part.trim().parse().ok()).collect();
    if !ids.contains(&id) {
        return Ok(());
    }
    let kept: Vec<String> = ids.iter().filter(|muted| **muted != id).map(i64::to_string).collect();
    app.db.set("alert_muted_nodes", &kept.join(","))
}

// ---- the rules ----

/// The rules as the last pass read them.
#[derive(Debug, Clone, PartialEq)]
pub struct Rules {
    token: String,
    chat: String,
    /// Where a webhook is posted, empty when none is configured. One address
    /// rather than a list: the second endpoint an operator wants is a thing they
    /// already have, and it can forward.
    webhook: String,
    /// The webhook's extra headers, as the panel wrote them. Parsed where they
    /// are used; see [`send_webhook`].
    headers: String,
    offline_minutes: i64,
    traffic_percent: i64,
    expiry_days: i64,
    resource_percent: i64,
    resource_minutes: i64,
    /// Nodes the operator asked not to hear about. A node here is not judged at
    /// all, which is a different thing from a rule being switched off: the rule
    /// still applies to every other node, and this one is excluded from all of
    /// them at once.
    muted: HashSet<i64>,
}

impl Rules {
    pub fn read(app: &App) -> Self {
        let number = |key: &str| app.db.get(key).and_then(|v| v.trim().parse().ok()).unwrap_or(0);
        Self {
            token: app.db.get("alert_telegram_token").unwrap_or_default().trim().to_owned(),
            chat: app.db.get("alert_telegram_chat").unwrap_or_default().trim().to_owned(),
            webhook: app.db.get("alert_webhook_url").unwrap_or_default().trim().to_owned(),
            headers: app.db.get("alert_webhook_headers").unwrap_or_default().trim().to_owned(),
            offline_minutes: number("alert_offline_minutes"),
            traffic_percent: number("alert_traffic_percent"),
            expiry_days: number("alert_expiry_days"),
            resource_percent: number("alert_resource_percent"),
            resource_minutes: number("alert_resource_minutes"),
            // A part that does not parse is skipped rather than failing the pass;
            // `muted_ok` is what keeps such a value from being stored. See there
            // for why the two are separate.
            muted: app
                .db
                .get("alert_muted_nodes")
                .unwrap_or_default()
                .split(',')
                .filter_map(|part| part.trim().parse().ok())
                .collect(),
        }
    }

    /// Whether the Telegram channel has somewhere to send to. A bot without a
    /// chat is not configured, the same way a chat without a bot is not.
    fn telegram(&self) -> bool {
        !self.token.is_empty() && !self.chat.is_empty()
    }

    /// The channels this hub is configured to send on, in the order they are
    /// tried. Both is a normal answer: the message is the same one, and an
    /// operator may want it in a chat and in whatever they run at home.
    fn channels(&self) -> Vec<Channel> {
        [Channel::Telegram, Channel::Webhook]
            .into_iter()
            .filter(|channel| match channel {
                Channel::Telegram => self.telegram(),
                Channel::Webhook => !self.webhook.is_empty(),
            })
            .collect()
    }

    /// Whether there is anywhere to send to at all. A rule switched on without a
    /// channel is not evaluated: there is no point recording what an operator was
    /// told when there is no way to tell them, and the first pass after a channel
    /// is configured should announce what is true then.
    fn addressed(&self) -> bool {
        !self.channels().is_empty()
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
        Some(Finding::raise("offline", "offline", format!("已离线 {}", human(silent))))
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
            "over" => format!("本月流量已用尽 {spent}（{percent}%）"),
            _ => format!("本月流量 {spent}（{percent}%）"),
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
        Some(Finding::raise("expiry", "soon", when))
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
        // `over` as well as `high`, because the state a pass writes is the one it
        // returns: once the escalation below has been announced, the row reads
        // `over`. Recognising only `high` fell back to it on the next pass, which
        // restarted the wait and announced the same overload again every
        // `resource_minutes` for as long as the machine stayed hot -- and rewrote
        // the row's `notified`, discarding a message that had not got away.
        let held = rules.resource_minutes <= 0
            || self.stored(node.id, kind).is_some_and(|s| {
                s.state == "over"
                    || (s.state == "high" && self.now.saturating_sub(s.since) >= rules.resource_minutes * 60)
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
        Some(Finding::raise(kind, "over", format!("{name} {percent:.0}%{held_for}")))
    }
}

/// Usage counted as the plan bills it: a node billed on upload alone measured as
/// the sum of both directions would be compared against the wrong figure.
///
/// The rule itself is `db::Traffic::month_used`, which the panel and this hub's
/// `notify` read as well, and it moved there when the hub took the figure over
/// from the panel: this used to be a second copy kept in step with the panel's
/// own `monthUsage`, which no longer exists.
fn usage(node: &Node, traffic: &Traffic) -> i64 {
    traffic.month_used(&node.traffic_mode)
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
            // A space jams the name and the figure together in chat; a colon would fight expiry dates.
            self.line = format!("{} · {}", self.label, self.line);
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
    // And the same for a muted node, for the same reason applied to one node: it
    // is excluded from every rule at once, so unmuting it has to report what holds
    // then rather than what held when it went quiet.
    for id in &rules.muted {
        app.db.forget_alerts_of(*id)?;
    }

    let pass = Pass {
        rules,
        states: &app.db.alert_states()?,
        now: Utc::now().timestamp(),
        today: Local::now().date_naive(),
        uptime,
    };

    let nodes = app.db.nodes()?;
    // An id in the list that names no node is dropped here. Deleting a node already
    // takes it out of the list, so what reaches this is a list an older build left
    // behind -- and clearing it is what keeps a stale entry from muting whatever
    // takes that id next. Nothing is written unless something is dangling.
    let live: HashSet<i64> = nodes.iter().map(|n| n.id).collect();
    let kept: HashSet<i64> = rules.muted.iter().copied().filter(|id| live.contains(id)).collect();
    if kept.len() != rules.muted.len() {
        let mut ids: Vec<i64> = kept.iter().copied().collect();
        ids.sort_unstable();
        let list: Vec<String> = ids.iter().map(i64::to_string).collect();
        app.db.set("alert_muted_nodes", &list.join(","))?;
    }
    let traffic = app.db.all_traffic();
    // Every node, every rule, one pass over the map of connected agents. A muted
    // node is dropped here rather than left to `judge`, because "not judged" and
    // "judged and found quiet" are not the same thing: the second still writes the
    // row that would suppress the message after unmuting. Held only for the
    // gather: the writes below and the request after them belong to no lock.
    let findings = {
        let agents = app.agents.read().unwrap_or_else(|e| e.into_inner());
        let none = Traffic::default();
        nodes
            .iter()
            .filter(|node| !kept.contains(&node.id))
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
        // Kept across a repeat, a retry and a clearing: the duration in the
        // message is how long the state lasted, not how long ago the row was last
        // written. A clearing in particular has to survive its own retry, or a
        // recovery that failed to send would come back half a minute later saying
        // "离线 30 秒" about an outage of ten minutes.
        let since = match stored {
            Some(s) if !changed || (send && finding.state.is_empty()) => s.since,
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
        // The heading above already says "已恢复", so the line spends its words on
        // the one thing the heading cannot say: how long the node was away.
        Some(away) => format!("{} · 离线 {away}", finding.label),

        // Unreachable: a state is only cleared against the row that recorded it,
        // and `record` drops a quiet finding that has no row. The name on its own
        // is still a whole line under that heading rather than a broken one.
        None => finding.label.clone(),
    }
}

/// Sends what is owed, then marks it told.
///
/// Where an alert can go. A hub with both configured posts to both.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Channel {
    Telegram,
    Webhook,
}

impl Channel {
    /// What this channel is called where a failure is reported: the hub's log,
    /// and the panel when it is the test message that failed.
    fn name(self) -> &'static str {
        match self {
            Channel::Telegram => "Telegram",
            Channel::Webhook => "Webhook",
        }
    }
}

/// Sends what a pass owes, over every channel that is configured.
///
/// A channel that refuses the message is logged and the pass carries on: an alert
/// that reached the operator by one route has been delivered, and retrying in
/// order to satisfy a second route that is misconfigured would repeat the first
/// one every thirty seconds until somebody noticed -- turning one outage into a
/// flood is a worse failure than the second channel missing it, and the log names
/// the channel that failed, which is what an operator needs to fix it.
///
/// Only a message no channel took is left owed, so it is tried again rather than
/// lost to one unreachable minute. A pass that produced several messages and
/// failed on a later one repeats the earlier ones; that is the price of not being
/// able to tell a delivered message from a lost one, and it is cheaper than
/// silence.
async fn deliver(app: &App, api: &str, rules: &Rules, owed: &[Finding]) -> Result<()> {
    let hub = hub_name(app);
    let channels = rules.channels();
    for message in render(owed) {
        let mut delivered = false;
        let mut failures = Vec::new();
        for channel in &channels {
            let sent = match channel {
                Channel::Telegram => send_telegram(&app.http, api, rules, &compose(&message, HTML)).await,
                Channel::Webhook => {
                    let text = compose(&message, PLAIN);
                    send_webhook(&app.http, rules, &hub, &text, &message).await
                }
            };
            match sent {
                Ok(()) => delivered = true,
                Err(e) => failures.push(format!("{}: {e:#}", channel.name())),
            }
        }
        if !delivered {
            anyhow::bail!("no channel took the message: {}", failures.join("; "));
        }
        for failure in failures {
            warn!("a channel did not take the alert -- {failure}");
        }
    }
    for finding in owed {
        app.db.alert_notified(finding.node, finding.kind, Utc::now().timestamp())?;
    }
    let names: Vec<&str> = channels.iter().map(|channel| channel.name()).collect();
    info!("sent {} alert line(s) on {}", owed.len(), names.join(", "));
    Ok(())
}

/// The address one message goes to.
fn endpoint(api: &str, token: &str) -> String {
    format!("{api}/bot{token}/sendMessage")
}

/// Posts one message to the configured chat.
///
/// The error from a failed request is rebuilt without its URL, because the URL
/// carries the bot token and this error is logged: a hub whose DNS was briefly
/// unreachable would otherwise write its own credential into its journal.
async fn send_telegram(client: &reqwest::Client, api: &str, rules: &Rules, text: &str) -> Result<()> {
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

/// Posts one message to the configured webhook.
///
/// The headers are parsed here rather than held parsed, because the setting is
/// the operator's own text and this is the only place a bad line can be named.
/// The panel refuses to store one that is not `Name: value`, so what is left to
/// fail is a name or a value the HTTP layer will not carry -- the same mistake
/// with the same remedy, and an error naming it either way.
///
/// The error is rebuilt without its URL for the same reason as Telegram's, and
/// with less of an excuse: `?token=` is how half of the webhook endpoints there
/// are authenticate, so the credential here is in the URL as often as not.
async fn send_webhook(
    client: &reqwest::Client,
    rules: &Rules,
    hub: &str,
    text: &str,
    lines: &[Line<'_>],
) -> Result<()> {
    let mut headers = reqwest::header::HeaderMap::new();
    for line in rules.headers.lines().filter(|line| !line.trim().is_empty()) {
        let (name, value) =
            line.split_once(':').ok_or_else(|| anyhow!("webhook header {line:?} is not Name: value"))?;
        let name = reqwest::header::HeaderName::from_bytes(name.trim().as_bytes())
            .map_err(|e| anyhow!("webhook header name {:?} is not one: {e}", name.trim()))?;
        let value = reqwest::header::HeaderValue::from_str(value.trim())
            .map_err(|e| anyhow!("webhook header {name} carries a value HTTP will not: {e}"))?;
        headers.insert(name, value);
    }
    let response = client
        .post(&rules.webhook)
        .headers(headers)
        .json(&webhook_body(hub, text, lines))
        .send()
        .await
        .map_err(|e| anyhow!("the webhook request failed: {}", e.without_url()))?;
    let status = response.status();
    if !status.is_success() {
        // Whatever the receiver said. A script's own 401 or its own exception text
        // is the only thing that distinguishes a wrong header from an endpoint
        // that is simply not there.
        let detail = response.text().await.unwrap_or_default();
        anyhow::bail!("the webhook refused the message ({status}): {}", truncate(&detail, 300));
    }
    Ok(())
}

/// One line of a message: the heading it belongs under, and the line itself.
type Line<'a> = (&'static str, &'a str);

/// One message's worth of the pass, in the order it is written.
///
/// The heading repeats on each of its lines rather than opening a group, so that a
/// formatter decides where to print it -- see [`compose`] -- and neither the split
/// in [`render`] nor the JSON in [`webhook_body`] needs a second structure to walk.
type Message<'a> = Vec<Line<'a>>;

/// The pass as one message, or as several when it has more to say than Telegram
/// will take.
///
/// Grouped by heading so that a node going down and a quota being passed are not
/// interleaved, and ordered so the thing an operator acts on first is at the top.
/// A group that outgrows one message continues into the next under a repeated
/// heading rather than being sent oversized, which Telegram would refuse and the
/// hub would then retry forever.
fn render(owed: &[Finding]) -> Vec<Message<'_>> {
    let mut ordered: Vec<(u8, &'static str, &str)> = owed
        .iter()
        .map(|f| {
            let (heading, rank) = heading(f.kind, f.state);
            (rank, heading, f.line.as_str())
        })
        .collect();
    // Stable, so nodes keep the order the database gave them within a group.
    ordered.sort_by_key(|(rank, _, _)| *rank);

    let mut messages: Vec<Message<'_>> = Vec::new();
    let mut current: Message<'_> = Vec::new();
    let mut weight = 0;
    for (_, heading, line) in ordered {
        // What the line costs the message it is about to join: itself, the dotted
        // prefix compose adds, and its newline, plus -- where its heading is not
        // already open there -- the heading, its tags, and the blank line that
        // separates it from the group above. A message with nothing in it has no
        // heading open, so the line that begins one pays for a heading too.
        let opens = match current.last() {
            None => true,
            Some((open, _)) => *open != heading,
        };
        let mut added = line.len()
            + 1
            + "· ".len()
            + if opens { heading.len() + 8 + if current.is_empty() { 0 } else { 1 } } else { 0 };
        if !current.is_empty() && weight + added > BUDGET {
            messages.push(std::mem::take(&mut current));
            weight = 0;
            // The line now opens a message of its own, which means it pays for the
            // heading it was going to inherit.
            added = line.len() + 1 + "· ".len() + heading.len() + 8;
        }

        weight += added;
        current.push((heading, line));
    }
    if !current.is_empty() {
        messages.push(current);
    }
    messages
}

/// A message written out for one channel: each line under its heading, the heading
/// printed again only where it changes.
///
/// `tag` is what a heading is wrapped in. Telegram's HTML parse mode needs the
/// `<b>`; a webhook's reader is a script, and would show the tags as text.
fn compose(message: &Message<'_>, tag: (&str, &str)) -> String {
    let (open_tag, close_tag) = tag;
    let mut out = String::new();
    let mut open = "";
    for (heading, line) in message {
        if *heading != open {
            if !out.is_empty() {
                out.push('\n');
            }
            out.push_str(open_tag);
            out.push_str(heading);
            out.push_str(close_tag);
            out.push('\n');
            open = heading;
        }
        // Presentation only: Finding.line and webhook lines[].text stay unprefixed.
        out.push_str("· ");
        out.push_str(line);
        out.push('\n');
    }
    out
}

/// What a webhook receives.
///
/// `text` is the message as [`compose`] writes it, so a receiver that only wants
/// to show somebody what happened can post that one field and ignore the rest.
/// `lines` is the same message taken apart, because the alternative for a script
/// is splitting `text` on newlines and guessing which half is a node's name and
/// which is the wording -- the coupling this format exists to avoid.
fn webhook_body(hub: &str, text: &str, lines: &[Line<'_>]) -> Value {
    json!({
        "hub": hub,
        "text": text,
        "lines": lines
            .iter()
            .map(|(heading, line)| json!({"heading": heading, "text": line}))
            .collect::<Vec<_>>(),
    })
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

/// What this hub calls itself in a message read away from the panel: the site
/// name the operator set, falling back to the word `/api/me` uses.
///
/// Not the binary's name. One Telegram chat can hold the alerts of several hubs,
/// and every one of them is "monitor-hub" -- the build's name, not the
/// operator's -- so a message from this hub would be indistinguishable from the
/// same message sent by any other. Whitespace counts as unset: the field is
/// cleared by emptying it, and "  测试消息" reads worse than the fallback.
fn hub_name(app: &App) -> String {
    app.db.get("site_name").filter(|name| !name.trim().is_empty()).unwrap_or_else(|| "Monitor".into())
}

/// Sends one message with the stored configuration, over every configured
/// channel.
///
/// The way to find out that a token or an address is wrong is here, while an
/// operator is looking at the page, rather than the first time a node goes down.
/// Deliberately not a GET: it puts a message in a chat and a request at a URL, and
/// a GET is something a browser, a link preview or a proxy may issue on its own.
///
/// One channel failing does not stop the other from being tried, and the answer
/// names which one failed: an operator who has just added a webhook needs to know
/// that the webhook is the broken half, not that "the test failed".
pub async fn test(_: Admin, State(app): State<Shared>) -> Response {
    let rules = Rules::read(&app);
    if !rules.addressed() {
        return (StatusCode::BAD_REQUEST, "先填写 Bot Token 和 Chat ID，或 Webhook 地址").into_response();
    }
    let hub = hub_name(&app);
    let text = format!("{hub}\n告警测试\n收到这条说明通道已经接通。");

    let mut failures = Vec::new();
    for channel in rules.channels() {
        let sent = match channel {
            Channel::Telegram => send_telegram(&app.http, TELEGRAM_API, &rules, &text).await,
            // No lines: a test message describes nothing. It is here to prove the
            // address and the headers, and a receiver that reads `lines` will find
            // it empty on this one call and populated on every real one.
            Channel::Webhook => send_webhook(&app.http, &rules, &hub, &text, &[]).await,
        };
        if let Err(e) = sent {
            failures.push(format!("{}：{e:#}", channel.name()));
        }
    }
    match failures.is_empty() {
        true => Json(json!({"ok": true})).into_response(),
        // The channel's own refusal, not a generic one: it is the only thing that
        // says which of the fields is wrong.
        false => (StatusCode::BAD_GATEWAY, failures.join("\n")).into_response(),
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
            webhook: String::new(),
            headers: String::new(),
            offline_minutes: 5,
            traffic_percent: 80,
            expiry_days: 7,
            resource_percent: 90,
            resource_minutes: 5,
            muted: HashSet::new(),
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
            ("alert_webhook_url", "https://example.com/hook"),
            ("alert_webhook_headers", "Authorization: Bearer abc"),
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
        assert_eq!(rules.webhook, stored[2].1);
        assert_eq!(rules.headers, stored[3].1);
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

    /// A webhook address has to be one this hub can post to. `http://` is allowed
    /// here where the agent mirror insists on `https://`: what travels this URL is
    /// a sentence about a node, not a binary another machine will execute.
    #[test]
    fn a_webhook_address_is_a_scheme_and_a_host() {
        assert!(webhook_ok("https://example.com/hook"));
        assert!(webhook_ok("http://127.0.0.1:8080/alerts"));
        assert!(webhook_ok("https://gotify.example.com/message?token=abc"));
        // A bare host is what a paste out of a browser's address bar looks like
        // when the scheme was in the part that got left behind.
        assert!(!webhook_ok("example.com/hook"));
        assert!(!webhook_ok("ftp://example.com/hook"));
        assert!(!webhook_ok("https://"));
        assert!(!webhook_ok("https:///hook"));
        // Whitespace is what a copy out of a chat window brings with it, and a URL
        // with one in it is not the URL the operator thinks they pasted.
        assert!(!webhook_ok("https://example.com/hook "));
        assert!(!webhook_ok("https://exa mple.com/hook"));
        assert!(!webhook_ok(""));
    }

    /// The headers are the operator's own lines, and every self-hosted endpoint
    /// documents them in this shape. A line the hub cannot parse is refused here
    /// rather than dropped at send time, where the endpoint's 401 would be the
    /// only sign of it.
    #[test]
    fn webhook_headers_are_name_colon_value_lines() {
        assert!(headers_ok(""), "empty is the default: no extra headers");
        assert!(headers_ok("Authorization: Bearer abc123"));
        assert!(headers_ok("X-Gotify-Key: AbCdEf\nContent-Type: application/json"));
        // The space after the colon is optional, and so is the value.
        assert!(headers_ok("X-Token:"));
        assert!(headers_ok("X-Token: "));
        assert!(headers_ok("\n\nAuthorization: x\n\n"), "blank lines are padding, not headers");

        assert!(!headers_ok("Authorization Bearer abc"), "no colon, so no name to send");
        assert!(!headers_ok(": abc"), "a value with nothing to attach it to");
        assert!(!headers_ok("Author ization: abc"), "a space is not allowed in a field name");
        assert!(!headers_ok("Authorization: abc\nnot a header"));
    }

    /// Ids and nothing else. The pass parses this list every tick and skips what
    /// does not parse, so a value that got through here would mute a different set
    /// of nodes than the page shows, and nothing would say so.
    #[test]
    fn a_mute_list_is_ids_and_only_ids() {
        assert!(muted_ok(""), "empty is the default: nobody muted");
        assert!(muted_ok("1"));
        assert!(muted_ok("1,2,3"));
        assert!(muted_ok(" 1 , 2 "), "the spacing the panel writes");
        assert!(!muted_ok("web"), "a name is not an id, and one can be renamed");
        assert!(!muted_ok("1,,2"), "an empty part is not a node");
        assert!(!muted_ok("0"), "ids start at one");
        assert!(!muted_ok("-3"));
        assert!(!muted_ok("1;2"));
        assert!(!muted_ok("1 2"));
    }

    /// The test message names the hub the operator is looking at, not the build.
    /// Every hub answers to "monitor-hub", so a chat holding the alerts of
    /// several of them could not tell which one spoke.
    #[test]
    fn a_hub_is_named_by_its_site_name_and_falls_back_when_it_is_unset() {
        let app = App::for_test(Db::open(":memory:").unwrap());
        assert_eq!(hub_name(&app), "Monitor", "the word /api/me falls back to");
        app.db.set("site_name", "Status").unwrap();
        assert_eq!(hub_name(&app), "Status");
        app.db.set("site_name", "   ").unwrap();
        assert_eq!(hub_name(&app), "Monitor", "cleared to whitespace is not a name");
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
        assert_eq!(found.line, "已离线 5 分钟");

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
        assert_eq!(at(1_000, 800).line, "本月流量 800 B / 1000 B（80%）");
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
        assert_eq!(soon.line, "3 天后到期（2026-09-18）");

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
        assert_eq!(over.line, "CPU 99%（持续 5 分钟）");

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
        assert_eq!(immediate.line, "CPU 99%");
    }

    /// An overload that keeps holding stays `over` rather than falling back to
    /// `high` and restarting its wait.
    ///
    /// The failure this pins: the state a pass writes is the one it returns, so the
    /// pass after an announced escalation finds `over` on the row. Reading only
    /// `high` as already held, it returned `high` again, reset `since`, and five
    /// minutes later announced the same overload a second time -- and never
    /// stopped, for as long as the machine stayed hot.
    #[test]
    fn an_overload_that_keeps_holding_is_not_announced_again() {
        let (app, id) = hub();
        let rules = rules();
        let now = 1_700_000_000;
        let hot = json!({"cpu": 99.0});
        // Keyed by the id this hub minted, not the helper's constant.
        let node = Node { id, ..node("web") };
        let row = |state: &str, since: i64| {
            let mut states = HashMap::new();
            states.insert((id, "cpu".to_owned()), AlertState { state: state.into(), since, notified: 0 });
            states
        };

        // The escalation, which is news. `record` writes the state it was handed,
        // so the row reads `over` from here on.
        let held = row("high", now - 300);
        let over = pass(&rules, &held, now).resource(&node, Some(&hot), "cpu").unwrap();
        assert_eq!(over.state, "over");
        assert_eq!(record(&app, &held, vec![over.named(&node)], now).unwrap().len(), 1);
        // Told, which is what `deliver` does once the message is away.
        app.db.alert_notified(id, "cpu", now).unwrap();

        let states = app.db.alert_states().unwrap();
        assert_eq!(states[&(id, "cpu".to_owned())].state, "over");
        assert_eq!(states[&(id, "cpu".to_owned())].since, now, "the escalation starts the state");

        // Still hot half a minute later: the same state, and nothing owed.
        let again = pass(&rules, &states, now + 30).resource(&node, Some(&hot), "cpu").unwrap();
        assert_eq!(again.state, "over", "an announced overload does not fall back to high");
        assert!(
            record(&app, &states, vec![again.named(&node)], now + 30).unwrap().is_empty(),
            "and is not news again thirty seconds later"
        );

        let states = app.db.alert_states().unwrap();
        assert_eq!(states[&(id, "cpu".to_owned())].since, now, "the wait is not restarted");

        // Nor five minutes in, which is where the fallback sent its second copy of
        // the same sentence.
        let later = pass(&rules, &states, now + 300).resource(&node, Some(&hot), "cpu").unwrap();
        assert_eq!(later.state, "over");
        assert!(
            record(&app, &states, vec![later.named(&node)], now + 300).unwrap().is_empty(),
            "no repeat at the moment a fresh wait would have elapsed"
        );
    }

    /// An escalation that never got away is still owed on the next pass.
    ///
    /// The row keeps `over`, so the pass that follows reads the same state and the
    /// `notified == 0` that means undelivered, and retries. Falling back to `high`
    /// instead rewrote `notified` with the current time, dropping the message with
    /// no trace anywhere.
    #[test]
    fn an_escalation_that_never_went_out_is_still_owed() {
        let (app, id) = hub();
        let rules = rules();
        let now = 1_700_000_000;
        let hot = json!({"cpu": 99.0});
        let node = Node { id, ..node("web") };
        let mut held = HashMap::new();
        held.insert(
            (id, "cpu".to_owned()),
            AlertState { state: "high".into(), since: now - 300, notified: 0 },
        );

        let over = pass(&rules, &held, now).resource(&node, Some(&hot), "cpu").unwrap();
        assert_eq!(record(&app, &held, vec![over.named(&node)], now).unwrap().len(), 1);

        // `deliver` never ran, so the row still says this is owed.
        let states = app.db.alert_states().unwrap();
        assert_eq!(states[&(id, "cpu".to_owned())].notified, 0, "recorded, not told");

        let again = pass(&rules, &states, now + 30).resource(&node, Some(&hot), "cpu").unwrap();
        assert_eq!(again.state, "over");
        assert_eq!(
            record(&app, &states, vec![again.named(&node)], now + 30).unwrap().len(),
            1,
            "an undelivered escalation is owed again rather than written off"
        );
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
        assert_eq!(back[0].line, "web · 离线 10 分钟");

        app.db.alert_notified(id, "offline", now + 600).unwrap();

        // And the quiet that follows is not news either.
        let states = app.db.alert_states().unwrap();
        assert!(record(&app, &states, vec![find("")], now + 630).unwrap().is_empty());
    }

    /// A recovery message that did not get away is owed again, and the retry must
    /// still name the length of the outage rather than the length of the retry.
    #[test]
    fn a_recovery_message_that_failed_to_send_still_names_the_whole_outage() {
        let (app, id) = hub();
        let now = 1_700_000_000;
        let find = |state: &'static str| line(id, "offline", state);

        // Down, and told.
        record(&app, &none(), vec![find("offline")], now).unwrap();
        app.db.alert_notified(id, "offline", now).unwrap();

        // Back up ten minutes later. Telegram refuses the recovery, so `deliver`
        // never reaches `alert_notified` and the row stays owed.
        let states = app.db.alert_states().unwrap();
        let back = record(&app, &states, vec![find("")], now + 600).unwrap();
        assert_eq!(back[0].line, "web · 离线 10 分钟");

        // The retry half a minute later says the same thing. How long ago the
        // message was first attempted is not how long the node was down.
        let states = app.db.alert_states().unwrap();
        let retry = record(&app, &states, vec![find("")], now + 630).unwrap();
        assert_eq!(retry.len(), 1, "still owed");
        assert_eq!(retry[0].line, "web · 离线 10 分钟");
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
                line: "db 3 天后到期".into(),
                ..Finding::quiet("expiry")
            },
            Finding {
                kind: "offline",
                state: "offline",
                line: "web · 已离线 5 分钟".into(),

                ..Finding::quiet("offline")
            },
            Finding {
                kind: "offline",
                state: "",
                line: "api 离线 9 分钟".into(),
                ..Finding::quiet("offline")
            },
            Finding {
                kind: "traffic",
                state: "warn",
                line: "db 本月流量 80%".into(),
                ..Finding::quiet("traffic")
            },
        ];
        let messages = render(&owed);
        assert_eq!(messages.len(), 1);
        let text = compose(&messages[0], HTML);
        assert!(text.starts_with("<b>离线</b>\n"), "{text}");
        let order: Vec<usize> =
            ["离线", "已恢复", "流量告警", "即将到期"].iter().map(|h| text.find(h).unwrap()).collect();
        assert!(order.windows(2).all(|w| w[0] < w[1]), "{text}");
        assert_eq!(text.matches("<b>").count(), 4);

        // The same message for a channel that renders no markup: the headings
        // stay, because they are what tells a reader what the lines below them
        // are about, and only the tags go.
        let plain = compose(&messages[0], PLAIN);
        assert!(plain.starts_with("离线\n"), "{plain}");
        assert!(!plain.contains('<') && !plain.contains('>'), "{plain}");
        assert!(plain.contains("web · 已离线 5 分钟"), "{plain}");
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
                line: format!("node-{i:04} 已离线 5 分钟"),
                ..Finding::quiet("offline")
            })
            .collect();
        let messages = render(&owed);
        assert!(messages.len() > 1, "one message for 400 nodes");
        for message in &messages {
            let text = compose(message, HTML);
            assert!(text.len() <= BUDGET, "{} characters", text.len());
            assert!(text.contains("<b>离线</b>"), "every message says what it is about");
        }
        // Every line survives the split exactly once.
        assert_eq!(messages.iter().map(|m| m.len()).sum::<usize>(), 400);
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

    /// A stand-in for whatever the operator runs at the other end. Records the
    /// headers as well as the body, because the headers are half of what a webhook
    /// is configured with and the half nothing else would notice going missing.
    async fn mock_webhook(
        status: StatusCode,
        answer: &'static str,
    ) -> (String, Arc<Mutex<Vec<(axum::http::HeaderMap, Value)>>>) {
        let seen: Arc<Mutex<Vec<(axum::http::HeaderMap, Value)>>> = Arc::default();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let sink = seen.clone();
        let router = axum::Router::new().fallback(move |headers: axum::http::HeaderMap, body: String| {
            let sink = sink.clone();
            async move {
                let body = serde_json::from_str(&body).unwrap_or(Value::Null);
                sink.lock().unwrap().push((headers, body));
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

    /// The same hub with the bot taken back out and a webhook put in its place, so
    /// that a test can tell the two channels apart by which one is configured.
    fn wired_webhook(url: &str) -> (App, i64) {
        let (app, id) = wired();
        app.db.set("alert_telegram_token", "").unwrap();
        app.db.set("alert_telegram_chat", "").unwrap();
        app.db.set("alert_webhook_url", url).unwrap();
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
            // The line as it lands, exactly: a list mark, the node's name, a middle
            // dot, then the wording. The whole message is pinned rather than its parts.
            assert_eq!(text, "<b>离线</b>\n· web · 已离线 10 分钟\n");
        }

        // Told once. The node is still down and the operator already knows.
        once(&app, &api, &rules, Duration::from_secs(3_600)).await.unwrap();
        assert_eq!(seen.lock().unwrap().len(), 1, "an unchanged condition is not repeated");
    }

    /// A muted node is not judged at all -- which is not the same as judged and
    /// found quiet. The quiet verdict still writes the row, and that row is what
    /// would suppress the first message after the mute is lifted.
    #[tokio::test]
    async fn a_muted_node_says_nothing_and_unmuting_it_reports_what_holds_then() {
        let (api, seen) = mock_telegram(StatusCode::OK, r#"{"ok":true}"#).await;
        let (app, id) = wired();

        // Ten minutes quiet is a message on the first pass; muted, it is not.
        app.db.set("alert_muted_nodes", &id.to_string()).unwrap();
        let rules = Rules::read(&app);
        assert!(rules.muted.contains(&id), "the id in the setting is the node that is muted");
        once(&app, &api, &rules, Duration::from_secs(3_600)).await.unwrap();
        assert!(seen.lock().unwrap().is_empty(), "a muted node says nothing");
        assert!(app.db.alert_states().unwrap().is_empty(), "and nothing is recorded about it");

        // Still down, now unmuted. The operator hears about the outage they muted
        // through rather than never, which is what a row written before the mute
        // would have bought them.
        app.db.set("alert_muted_nodes", "").unwrap();
        let rules = Rules::read(&app);
        once(&app, &api, &rules, Duration::from_secs(3_600)).await.unwrap();
        let sent = seen.lock().unwrap();
        assert_eq!(sent.len(), 1, "unmuting reports the condition that holds");
        assert_eq!(sent[0]["text"].as_str().unwrap(), "<b>离线</b>\n· web · 已离线 10 分钟\n");
    }

    /// Muting is per node, not a switch for the feature: the same pass still
    /// announces every other node.
    #[tokio::test]
    async fn muting_one_node_leaves_the_others_alone() {
        let (api, seen) = mock_telegram(StatusCode::OK, r#"{"ok":true}"#).await;
        let (app, first) = wired();
        let second = app.db.create_node(&node("db"), "second-token").unwrap();
        app.db.touch_seen(second, Utc::now().timestamp() - 600).unwrap();

        app.db.set("alert_muted_nodes", &first.to_string()).unwrap();
        let rules = Rules::read(&app);
        once(&app, &api, &rules, Duration::from_secs(3_600)).await.unwrap();

        let sent = seen.lock().unwrap();
        assert_eq!(sent.len(), 1, "the node that is not muted still gets through");
        let text = sent[0]["text"].as_str().unwrap();
        assert!(text.contains("db · 已离线"), "{text}");

        assert!(!text.contains("web"), "{text}");
    }

    /// Deleting a muted node takes it out of the list, and the id it held comes back
    /// with the next node created: an entry left behind would silence a machine
    /// nobody muted, and do it silently, because the pass never looks at a muted
    /// node. `unmute` is what a deletion calls -- `api::delete_node` -- and the list
    /// holds ids, so nothing in it could tell the two nodes apart afterwards.
    #[tokio::test]
    async fn deleting_a_muted_node_unmutes_the_next_one_to_take_its_id() {
        let (api, seen) = mock_telegram(StatusCode::OK, r#"{"ok":true}"#).await;
        let (app, gone) = wired();
        app.db.set("alert_muted_nodes", &gone.to_string()).unwrap();
        assert!(app.db.delete_node(gone).unwrap());
        unmute(&app, gone).unwrap();
        assert_eq!(app.db.get("alert_muted_nodes").as_deref(), Some(""));

        // The id comes back with the next node, which is what made the entry
        // dangerous rather than merely stale.
        let reborn = app.db.create_node(&node("reborn"), "reborn-token").unwrap();
        assert_eq!(reborn, gone, "SQLite hands a deleted node's id to the next one");
        app.db.touch_seen(reborn, Utc::now().timestamp() - 600).unwrap();

        let rules = Rules::read(&app);
        once(&app, &api, &rules, Duration::from_secs(3_600)).await.unwrap();
        let sent = seen.lock().unwrap();
        assert_eq!(sent.len(), 1, "the node that took the id is announced");
        assert_eq!(sent[0]["text"].as_str().unwrap(), "<b>离线</b>\n· reborn · 已离线 10 分钟\n");
    }

    /// An id in the list that no node holds is dropped by the next pass. A list an
    /// older build left behind is where one comes from -- it had no `unmute` -- and
    /// clearing it now is what keeps it from muting whatever takes that id later.
    #[tokio::test]
    async fn an_id_the_list_holds_that_no_node_does_is_dropped_by_the_pass() {
        let (api, _) = mock_telegram(StatusCode::OK, r#"{"ok":true}"#).await;
        let (app, live) = wired();
        app.db.set("alert_muted_nodes", &format!("{live},41")).unwrap();

        let rules = Rules::read(&app);
        once(&app, &api, &rules, Duration::from_secs(3_600)).await.unwrap();
        assert_eq!(
            app.db.get("alert_muted_nodes").unwrap_or_default(),
            live.to_string(),
            "the id that names a node is kept, the one that names none is dropped"
        );
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
        let failure =
            send_telegram(&app.http, "http://127.0.0.1:1", &rules, "hello").await.unwrap_err().to_string();
        assert!(failure.contains("telegram request failed"), "{failure}");
        assert!(!failure.contains(TOKEN), "the token is in the URL and must not reach the log: {failure}");
    }

    /// A hub whose only channel is a webhook, and what that channel receives: the
    /// message, plus the same message taken apart so that a script does not have
    /// to split the text and guess which half is a node's name.
    #[tokio::test]
    async fn a_webhook_receives_the_message_and_the_same_thing_taken_apart() {
        let (url, seen) = mock_webhook(StatusCode::OK, "ok").await;
        let (app, _) = wired_webhook(&url);
        app.db.set("alert_webhook_headers", "Authorization: Bearer s3cret\nX-Tag: home").unwrap();

        let rules = Rules::read(&app);
        assert!(rules.addressed(), "an address is all a webhook needs to be sent to");
        once(&app, &url, &rules, Duration::from_secs(3_600)).await.unwrap();

        {
            let sent = seen.lock().unwrap();
            assert_eq!(sent.len(), 1, "one pass, one request");
            let (headers, body) = &sent[0];
            // The operator's own lines, sent as written. Nothing else would notice
            // one of them being dropped, because the receiver answers the same
            // either way.
            assert_eq!(headers.get("authorization").unwrap().to_str().unwrap(), "Bearer s3cret");
            assert_eq!(headers.get("x-tag").unwrap().to_str().unwrap(), "home");
            assert_eq!(body["hub"], "Monitor", "no site name is set, so the fallback names it");
            assert_eq!(body["text"], "离线\n· web · 已离线 10 分钟\n");
            assert_eq!(body["lines"][0]["heading"], "离线");
            assert_eq!(body["lines"][0]["text"], "web · 已离线 10 分钟");
        }

        // Told once. The node is still down and the operator already knows.
        once(&app, &url, &rules, Duration::from_secs(3_600)).await.unwrap();
        assert_eq!(seen.lock().unwrap().len(), 1, "an unchanged condition is not repeated");
    }

    /// Both channels are configured, and one of them is not there. The alert
    /// reached the operator by the other route, so it has been delivered: retrying
    /// in order to satisfy the broken one would repeat the working one every
    /// thirty seconds, which turns one outage into a flood.
    #[tokio::test]
    async fn a_broken_second_channel_does_not_make_the_first_one_repeat() {
        let (api, seen) = mock_telegram(StatusCode::OK, r#"{"ok":true}"#).await;
        let (app, id) = wired();
        // Port 1 on loopback is reserved and nothing here listens on it.
        app.db.set("alert_webhook_url", "http://127.0.0.1:1/hook").unwrap();
        let rules = Rules::read(&app);
        assert_eq!(rules.channels(), vec![Channel::Telegram, Channel::Webhook]);

        once(&app, &api, &rules, Duration::from_secs(3_600)).await.unwrap();

        assert_eq!(seen.lock().unwrap().len(), 1, "the channel that works got it");
        assert!(
            app.db.alert_states().unwrap()[&(id, "offline".to_owned())].notified > 0,
            "and it is on record as told, which is what stops the repeat"
        );
        once(&app, &api, &rules, Duration::from_secs(3_600)).await.unwrap();
        assert_eq!(seen.lock().unwrap().len(), 1, "so the next pass says nothing");
    }

    /// A webhook that refuses the message leaves the alert owed, the same way a
    /// refused chat does: nothing reached the operator, so nothing is recorded as
    /// having been said.
    #[tokio::test]
    async fn a_refused_webhook_leaves_the_alert_owed() {
        let (url, seen) = mock_webhook(StatusCode::UNAUTHORIZED, "bad key").await;
        let (app, id) = wired_webhook(&url);
        let rules = Rules::read(&app);

        let failure = once(&app, &url, &rules, Duration::from_secs(3_600)).await.unwrap_err().to_string();
        assert!(failure.contains("bad key"), "the receiver's own words name the problem: {failure}");
        assert!(failure.contains("Webhook"), "and which channel said them: {failure}");
        assert_eq!(seen.lock().unwrap().len(), 1);

        assert_eq!(app.db.alert_states().unwrap()[&(id, "offline".to_owned())].notified, 0);
        assert!(once(&app, &url, &rules, Duration::from_secs(3_600)).await.is_err());
        assert_eq!(seen.lock().unwrap().len(), 2, "tried again");
    }

    /// The webhook URL is the operator's, and `?token=` is how half of these
    /// endpoints authenticate -- so it carries a credential as often as not, and
    /// this error is logged.
    #[tokio::test]
    async fn a_request_that_never_arrived_does_not_put_the_webhook_token_in_the_log() {
        let (app, _) = wired();
        let rules = Rules { webhook: "http://127.0.0.1:1/hook?token=s3cret".into(), ..rules() };
        let failure = send_webhook(&app.http, &rules, "Monitor", "hello", &[]).await.unwrap_err().to_string();
        assert!(failure.contains("webhook request failed"), "{failure}");
        assert!(!failure.contains("s3cret"), "the token is in the URL and must not reach the log: {failure}");
    }
}
