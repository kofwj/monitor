//! Sustained resource use, announced through `notify`.
//!
//! This is what is left of the fork's own alerting now that the two systems are
//! one. `notify` owns the channels, the message templates, the queue and its
//! retries, and judges offline and recovery, traffic, expiry and sign-ins; this
//! module judges the one thing it has no rule for -- CPU, memory or disk held over
//! a threshold -- and hands each finding to [`notify::send`]. An operator therefore
//! configures channels and wording in one place, and hears about an event once.
//!
//! What it kept from the fork's engine is the part worth having: the `alert_state`
//! row. A reading is news only when it *changes* into `over`, and that comparison
//! is against a table rather than against memory, so a hub that restarts in the
//! middle of an overload does not announce it a second time, and a reading that has
//! been high for ten minutes is not repeated on every pass.
//!
//! Every rule is a small state machine over one node, so the decision and the
//! wording are plain functions over values: no clock, no socket, no hub. The loop
//! at the bottom only gathers, records and hands over.

use std::collections::HashMap;
use std::time::Duration;

use anyhow::Result;
use chrono::Utc;
use serde_json::Value;
use tracing::warn;

use crate::agent_ws::Agent;
use crate::db::{AlertState, Node};
use crate::notify::{self, Note};
use crate::{App, Shared};

/// How often every rule is evaluated.
///
/// The shortest threshold worth configuring is a minute, so half a minute is the
/// resolution that makes it mean what it says: a reading that crosses its
/// threshold just after a pass is announced within one of these.
const TICK: Duration = Duration::from_secs(30);

/// How many nodes one message names before it counts the rest.
const LISTED: usize = 20;

/// What the notes carry as their event, for a template that wants to tell them
/// apart and for the log line when a channel refuses one.
const EVENT: &str = "resource";

/// The keys this engine reads. The three that used to sit beside them are gone:
/// offline, traffic and expiry are `notify`'s rules now.
///
/// Test-only, because production reads each key by name where it is used. This
/// list exists so that a test can assert the settings route accepts all of them:
/// the two are edited in different files, and either way they can disagree is
/// silent -- a field that can be typed into and never saved, or one that reloads
/// blank however many times it is saved.
#[cfg(test)]
pub const SETTINGS: [&str; 2] = ["alert_resource_percent", "alert_resource_minutes"];

/// The rules as the last pass read them.
#[derive(Debug, Clone, PartialEq)]
pub struct Rules {
    resource_percent: i64,
    resource_minutes: i64,
    /// Whether the notify page has a channel configured at all.
    ///
    /// Read from the two keys `notify`'s own channels are built from, in the same
    /// shape: a bot without a chat is not a channel, and neither is a chat without
    /// a bot. Read here rather than asked of `notify`, whose channel list is
    /// private -- a rule switched on with nowhere to send is not evaluated, and
    /// the first pass after a channel is configured is what announces what holds
    /// then.
    addressed: bool,
}

impl Rules {
    pub fn read(app: &App) -> Self {
        let number = |key: &str| app.db.get(key).and_then(|v| v.trim().parse().ok()).unwrap_or(0);
        let text = |key: &str| app.db.get(key).unwrap_or_default().trim().to_owned();
        let telegram = !text("notify_telegram_token").is_empty() && !text("notify_telegram_chat").is_empty();
        Self {
            resource_percent: number("alert_resource_percent"),
            resource_minutes: number("alert_resource_minutes"),
            addressed: telegram || !text("notify_webhook_url").is_empty(),
        }
    }

    /// Which rules are switched on. A threshold of zero is off, the same way a
    /// node with a traffic limit of zero has no limit.
    ///
    /// One threshold covers all three kinds, so they switch together -- and a kind
    /// switched off has its stored state dropped, so switching it back on reports
    /// the state of the world rather than the state it was left holding.
    fn switched_on(&self) -> [(&'static str, bool); 3] {
        let on = self.resource_percent > 0;
        [("cpu", on), ("mem", on), ("disk", on)]
    }
}

/// Everything one pass reads once and every rule then needs.
struct Pass<'a> {
    rules: &'a Rules,
    /// What the previous pass recorded, keyed by node and kind. The resource rule
    /// reads its own row back out of it to know how long a reading has held.
    states: &'a HashMap<(i64, String), AlertState>,
    now: i64,
}

impl Pass<'_> {
    fn stored(&self, node: i64, kind: &str) -> Option<&AlertState> {
        self.states.get(&(node, kind.to_owned()))
    }

    /// Everything the rules have to say about one node, in a fixed order.
    fn judge(&self, node: &Node, live: Option<&Agent>) -> Vec<Finding> {
        let metrics = live.map(|a| &a.metrics).filter(|m| m.is_object());
        ["cpu", "mem", "disk"]
            .into_iter()
            .filter_map(|kind| self.resource(node, metrics, kind))
            .map(|f| f.named(node))
            .collect()
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
        // `resource_minutes` for as long as the machine stayed hot.
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

/// One reading as a percentage of its capacity.
///
/// The capacities come from the report rather than from the stored node, for the
/// reason `api::node_view` gives: a machine that gained a disk while the agent was
/// running has a stored figure that is stale until the next reconnect, which may
/// be days away. The stored figure is the fallback for a report that omits the
/// capacity it is using.
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
    /// message is composed, so that naming a node costs no query.
    label: String,
    kind: &'static str,
    /// What this pass puts in `alert_state`, empty when there is nothing to
    /// report. Compared against the stored value to tell a change from a repeat.
    state: &'static str,
    /// The detail for the operator, without the node's name: whoever sends it
    /// knows the name, and one message carries several nodes.
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
        self.label = node.name.clone();
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
/// point of the setting. Leaving the state is not a message at all -- the reading
/// falling back under its threshold is the operator's own doing or the machine's,
/// and pairing an event with its recovery is `notify`'s, for the events it judges.
fn announces(state: &str) -> bool {
    !state.is_empty() && state != "high"
}

// ---- the loop ----

/// Evaluates every rule every [`TICK`] and hands whatever changed to `notify`.
pub async fn run(app: Shared) {
    let mut ticker = tokio::time::interval(TICK);
    loop {
        ticker.tick().await;
        let rules = Rules::read(&app);
        if let Err(e) = once(&app, &rules).await {
            warn!("the resource pass failed: {e:#}");
        }
    }
}

/// One pass: gather, record, hand over.
async fn once(app: &App, rules: &Rules) -> Result<()> {
    if !rules.addressed {
        // A hub with nowhere to send has nothing to remember: these rows record
        // what the operator was told, and none of it was. Forgetting them here is
        // also what makes configuring a channel announce the conditions that
        // already hold -- machines hot right now -- instead of waiting for each of
        // them to happen a second time.
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

    let pass = Pass { rules, states: &app.db.alert_states()?, now: Utc::now().timestamp() };

    // Every node, every kind, one pass over the map of connected agents. A node
    // with notifications switched off is dropped here rather than left to `judge`,
    // because "not judged" and "judged and found quiet" are not the same thing:
    // the second still writes the row that would suppress the message after
    // switching it back on. Held only for the gather.
    let findings = {
        let agents = app.agents.read().unwrap_or_else(|e| e.into_inner());
        app.db
            .nodes()?
            .iter()
            .filter(|node| node.notify)
            .flat_map(|node| pass.judge(node, agents.get(&node.id)))
            .collect()
    };

    for note in notes(&record(app, pass.states, findings, pass.now)?) {
        notify::send(app, note);
    }
    Ok(())
}

/// Writes what this pass decided, and returns what still owes the operator a
/// message.
///
/// The two are one function because they are one decision: whether a state is
/// news is the transition out of the stored row, and the row is what the write
/// puts there.
///
/// The row is also the only part of this that survives a restart. Delivery does
/// not: a note handed to `notify` is that system's to retry (three attempts per
/// channel) or to drop, so `notified` records when a message was handed over
/// rather than when a channel accepted it.
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
            announces(finding.state)
        } else {
            // A row an earlier build left owed (`notified` still zero) is
            // announced here: it was never delivered, and this pass is the last
            // thing that knows. A row this build writes is never in that state --
            // it is handed over in the same pass that writes it.
            !finding.state.is_empty() && stored.is_some_and(|s| s.notified == 0)
        };
        // Kept across a repeat: the duration in the message is how long the state
        // lasted, not how long ago the row was last written.
        let since = match stored {
            Some(s) if !changed => s.since,
            _ => now,
        };
        app.db.set_alert_state(finding.node, finding.kind, finding.state, since, now)?;
        if send {
            owed.push(finding);
        }
    }
    Ok(owed)
}

/// The message this pass produced, in the shape `notify` sends.
///
/// One note for the pass rather than one per node per kind: an operator with three
/// machines hot at once wants one message about it, which is what `notify` does
/// with the events it judges itself. `notify`'s templates decide the wording that
/// reaches the operator; the title and the detail here are what they are rendered
/// from.
fn notes(owed: &[Finding]) -> Vec<Note> {
    if owed.is_empty() {
        return Vec::new();
    }
    let listed = |f: &Finding| format!("{} · {}", f.label, f.line);
    let (title, message) = match owed {
        [one] => (format!("⚠️ {} 占用超阈值", one.label), one.line.clone()),
        many => {
            let mut lines: Vec<String> = many.iter().take(LISTED).map(listed).collect();
            if many.len() > LISTED {
                lines.push(format!("……另外 {} 台", many.len() - LISTED));
            }
            (format!("⚠️ {} 台节点占用超阈值", many.len()), lines.join("\n"))
        }
    };
    let node = owed.iter().map(|f| f.label.as_str()).collect::<Vec<_>>().join(", ");
    vec![Note { event: EVENT, node, title, message, ..Default::default() }]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::Db;
    use crate::db::NodePatch;
    use serde_json::json;
    use tokio::sync::mpsc;

    fn app() -> App {
        App::for_test(Db::open(":memory:").unwrap())
    }

    fn node(name: &str) -> Node {
        Node { name: name.into(), notify: true, ..Default::default() }
    }

    fn rules(percent: i64, minutes: i64) -> Rules {
        Rules { resource_percent: percent, resource_minutes: minutes, addressed: true }
    }

    /// An agent whose latest report carries one reading.
    fn live(cpu: f64) -> Agent {
        let (tx, _rx) = mpsc::channel(1);
        // `metrics` is public where the rest of the agent's session is not.
        let mut agent = Agent::new(1, tx);
        agent.metrics = json!({ "cpu": cpu });
        agent
    }

    /// A pass over one node, which is what a rule test needs.
    fn pass<'a>(rules: &'a Rules, states: &'a HashMap<(i64, String), AlertState>, now: i64) -> Pass<'a> {
        Pass { rules, states, now }
    }

    /// One stored row, as a previous pass would have left it.
    fn holding(
        node: i64,
        kind: &'static str,
        state: &'static str,
        since: i64,
    ) -> HashMap<(i64, String), AlertState> {
        [((node, kind.to_owned()), AlertState { state: state.into(), since, notified: 1 })]
            .into_iter()
            .collect()
    }

    #[test]
    fn a_reading_is_a_share_of_the_capacity_the_report_carries() {
        let stored = Node { mem_total: 1024, disk_total: 4096, ..node("web") };
        assert_eq!(reading(&stored, &json!({"cpu": 42.5}), "cpu"), Some(42.5));
        assert_eq!(reading(&stored, &json!({"mem_used": 512, "mem_total": 2048}), "mem"), Some(25.0));
        assert_eq!(reading(&stored, &json!({"disk_used": 1024, "disk_total": 8192}), "disk"), Some(12.5));

        // The stored capacity is the fallback for a report that omits the one it
        // is measured against -- and a machine with no capacity at all is not a
        // machine at 0% of one.
        assert_eq!(reading(&stored, &json!({"mem_used": 512}), "mem"), Some(50.0));
        assert_eq!(reading(&stored, &json!({"disk_used": 1024}), "disk"), Some(25.0));
        assert_eq!(reading(&node("web"), &json!({"mem_used": 512}), "mem"), None);
        assert_eq!(reading(&stored, &json!({"cpu": f64::NAN}), "cpu"), None);
    }

    /// A threshold crossed for a moment is not news: the reading has to hold for
    /// the minutes the operator asked for, and the row is where those minutes are
    /// counted.
    #[test]
    fn a_reading_has_to_hold_before_it_is_reported() {
        let web = node("web");
        let configured = rules(90, 5);
        let agent = live(95.0);

        assert_eq!(
            pass(&configured, &HashMap::new(), 1_000).judge(&web, Some(&agent))[0].state,
            "high",
            "the first crossing is not yet over"
        );
        let early = holding(web.id, "cpu", "high", 1_000);
        assert_eq!(pass(&configured, &early, 1_100).judge(&web, Some(&agent))[0].state, "high");
        assert_eq!(pass(&configured, &early, 1_300).judge(&web, Some(&agent))[0].state, "over");

        // Under it again, or not reporting at all: the row clears rather than
        // counting towards a threshold that is no longer crossed.
        let over = holding(web.id, "cpu", "over", 1_000);
        assert_eq!(pass(&configured, &over, 1_300).judge(&web, Some(&live(50.0)))[0].state, "");
        assert_eq!(pass(&configured, &over, 1_300).judge(&web, None)[0].state, "");
        // A kind switched off says nothing at all, not even "quiet".
        assert!(pass(&rules(0, 5), &HashMap::new(), 1_000).judge(&web, Some(&agent)).is_empty());
    }

    /// What the row buys: the same overload, still holding, is one message.
    #[test]
    fn an_overload_that_keeps_holding_is_announced_once() {
        let app = app();
        let web = node("web");
        let id = app.db.create_node(&web, "tok").unwrap();
        // The id the row was minted under, which is not the one the helper's node
        // carries: `alert_state` has a foreign key to `node`.
        let web = Node { id, ..web };
        let finding = || Finding::raise("cpu", "over", "CPU 95%（持续 5 分钟）".into()).named(&web);

        let owed = record(&app, &HashMap::new(), vec![finding()], 1_000).unwrap();
        assert_eq!(owed.len(), 1, "entering the state is news");
        assert_eq!(owed[0].line, "CPU 95%（持续 5 分钟）", "the detail is what the message carries");

        let stored = app.db.alert_states().unwrap();
        assert!(
            record(&app, &stored, vec![finding()], 1_100).unwrap().is_empty(),
            "still true, not news again"
        );
        // And the row kept the moment the state was entered, which is what a
        // duration in a later message is measured from.
        assert_eq!(app.db.alert_states().unwrap()[&(id, "cpu".into())].since, 1_000);
    }

    /// A row an earlier build left owed is announced once more: it was never
    /// delivered, and nothing else knows.
    #[test]
    fn a_row_an_earlier_build_left_owed_is_announced_once_more() {
        let app = app();
        let web = node("web");
        let id = app.db.create_node(&web, "tok").unwrap();
        app.db.set_alert_state(id, "cpu", "over", 1_000, 0).unwrap();
        let web = Node { id, ..web };
        let finding = Finding::raise("cpu", "over", "CPU 95%".into()).named(&web);

        let owed = record(&app, &app.db.alert_states().unwrap(), vec![finding], 1_100).unwrap();
        assert_eq!(owed.len(), 1);
        let again = Finding::raise("cpu", "over", "CPU 95%".into()).named(&web);
        assert!(record(&app, &app.db.alert_states().unwrap(), vec![again], 1_200).unwrap().is_empty());
    }

    /// The message itself, in the shape `notify` sends: one node named in the
    /// title, or a count when the pass found several.
    #[test]
    fn one_message_names_the_nodes_and_counts_the_rest() {
        let web = Finding::raise("cpu", "over", "CPU 95%（持续 5 分钟）".into()).named(&node("web"));
        let alone = notes(&[web]);
        assert_eq!(alone.len(), 1);
        assert_eq!(alone[0].title, "⚠️ web 占用超阈值");
        assert_eq!(alone[0].message, "CPU 95%（持续 5 分钟）");
        assert_eq!(alone[0].node, "web", "the templates read the node names from here");
        assert_eq!(alone[0].event, EVENT);

        let mut owed = Vec::new();
        for name in ["a", "b", "c"] {
            owed.push(Finding::raise("mem", "over", "内存 97%".into()).named(&node(name)));
        }
        let many = notes(&owed);
        assert_eq!(many[0].title, "⚠️ 3 台节点占用超阈值");
        assert_eq!(many[0].message, "a · 内存 97%\nb · 内存 97%\nc · 内存 97%");
        assert!(notes(&[]).is_empty());
    }

    /// End to end: a pass over a hot node hands one note to `notify`'s queue, and
    /// a node with notifications switched off hands over nothing.
    #[tokio::test]
    async fn a_pass_hands_one_note_to_notify_and_skips_the_nodes_switched_off() {
        let (tx, mut rx) = mpsc::channel(4);
        let mut app = app();
        app.notes = tx;
        app.db.set("notify_telegram_token", "1:abcdef").unwrap();
        app.db.set("notify_telegram_chat", "-100123").unwrap();
        app.db.set("alert_resource_percent", "90").unwrap();
        app.db.set("alert_resource_minutes", "5").unwrap();

        let hot = app.db.create_node(&node("hot"), "tok-hot").unwrap();
        let quiet = app.db.create_node(&node("quiet"), "tok-quiet").unwrap();
        // The per-node switch is a column, and `create_node` leaves it at its
        // default: this is the write the node dialog makes when it is ticked.
        app.db.update_node(hot, &NodePatch { notify: Some(true), ..Default::default() }).unwrap();
        let held = Utc::now().timestamp() - 600;
        for id in [hot, quiet] {
            app.db.set_alert_state(id, "cpu", "high", held, 1).unwrap();
            app.agents.write().unwrap().insert(id, live(95.0));
        }

        once(&app, &Rules::read(&app)).await.unwrap();

        let note = rx.try_recv().expect("the hot node's reading reached the queue");
        assert_eq!(note.event, "resource");
        assert_eq!(note.node, "hot");
        assert!(note.title.contains("hot"), "{:?}", note.title);
        assert!(note.message.starts_with("CPU 95%"), "{:?}", note.message);
        assert!(rx.try_recv().is_err(), "the node switched off is not judged at all");
        // The row is what stops the next pass saying it again.
        assert_eq!(app.db.alert_states().unwrap()[&(hot, "cpu".into())].state, "over");
        assert!(app
            .db
            .alert_states()
            .unwrap()
            .get(&(quiet, "cpu".into()))
            .is_some_and(|s| s.state == "high"));
    }

    /// A hub with nowhere to send remembers nothing, so that configuring a channel
    /// announces what holds then rather than what held all along.
    #[tokio::test]
    async fn without_a_channel_nothing_is_recorded() {
        let app = app();
        app.db.set("alert_resource_percent", "90").unwrap();
        let id = app.db.create_node(&node("hot"), "tok").unwrap();
        app.db.set_alert_state(id, "cpu", "over", 1_000, 1).unwrap();

        once(&app, &Rules::read(&app)).await.unwrap();
        assert!(app.db.alert_states().unwrap().is_empty(), "the rows go back to being news");
    }
}
