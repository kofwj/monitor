//! Sessions, the local emergency password, and GitHub single sign-on.
//!
//! GitHub is the primary sign-in path. The local password exists so that a
//! broken OAuth app or an unreachable github.com cannot lock the owner out.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::Argon2;
use axum::extract::{ConnectInfo, Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Redirect, Response};
use axum::Json;
use chrono::Utc;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use tokio::sync::Semaphore;
use tracing::{info, warn};

use crate::App;

pub const COOKIE: &str = "monitor_session";
const STATE_COOKIE: &str = "monitor_oauth_state";
const SESSION_DAYS: i64 = 14;
/// Failed password attempts allowed per address before it is shut out.
const MAX_ATTEMPTS: u32 = 5;
const LOCKOUT: Duration = Duration::from_secs(900);

/// How many password checks may run concurrently.
///
/// argon2 is deliberately expensive: one attempt costs 19 MiB and a tenth of a
/// core-second. Unbounded, that cost becomes a lever rather than a defence --
/// the lockout below bounds attempts per address, but nothing bounds the number
/// of addresses, which on IPv6 is a /64 the caller already controls.
///
/// Fixed at one: any limit at or above what the machine can run concurrently is
/// no limit at all. argon2 saturates a core, so a gate of four on a three-core
/// hub never reached four in flight and admitted a flood untouched -- 570 MB
/// against a unit file allowing 256. At one, 633 of 640 attempts are refused.
/// Deriving it from the core count would reopen the hole on smaller machines.
///
/// Refused rather than queued: a queue admits the same flood, merely later. The
/// cost is that two simultaneous sign-ins require one to retry.
const PASSWORD_CHECKS: usize = 1;
static PASSWORD_GATE: Semaphore = Semaphore::const_new(PASSWORD_CHECKS);

pub fn sha256(value: &str) -> String {
    hex::encode(Sha256::digest(value.as_bytes()))
}

pub fn random_token() -> String {
    hex::encode(rand::random::<[u8; 32]>())
}

pub fn hash_password(password: &str) -> Result<String> {
    let salt =
        SaltString::encode_b64(&rand::random::<[u8; 16]>()).map_err(|e| anyhow::anyhow!("salt: {e}"))?;
    Ok(Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| anyhow::anyhow!("hash password: {e}"))?
        .to_string())
}

fn verify_password(password: &str, stored: &str) -> bool {
    PasswordHash::new(stored)
        .map(|parsed| Argon2::default().verify_password(password.as_bytes(), &parsed).is_ok())
        .unwrap_or(false)
}

/// Per-address failure counter for the password endpoint.
pub struct Throttle {
    seen: Mutex<HashMap<IpAddr, (u32, Instant)>>,
    /// How long a failure is remembered. A field rather than the constant so
    /// tests can observe a lockout expire without sleeping for 15 minutes.
    window: Duration,
}

impl Default for Throttle {
    fn default() -> Self {
        Self { seen: Mutex::default(), window: LOCKOUT }
    }
}

impl Throttle {
    pub(crate) fn locked(&self, ip: IpAddr) -> bool {
        let mut map = self.seen.lock().unwrap_or_else(|e| e.into_inner());
        match map.get(&ip) {
            Some((n, since)) if since.elapsed() < self.window => *n >= MAX_ATTEMPTS,
            Some(_) => {
                map.remove(&ip);
                false
            }
            None => false,
        }
    }

    pub(crate) fn record_failure(&self, ip: IpAddr) {
        let mut map = self.seen.lock().unwrap_or_else(|e| e.into_inner());
        // Addresses past their window are dropped here rather than allowed to
        // accumulate, which also restarts the count for a returning address.
        map.retain(|_, (_, since)| since.elapsed() < self.window);
        map.entry(ip).or_insert((0, Instant::now())).0 += 1;
    }

    pub(crate) fn clear(&self, ip: IpAddr) {
        self.seen.lock().unwrap_or_else(|e| e.into_inner()).remove(&ip);
    }
}

fn cookie_value(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get(header::COOKIE)?
        .to_str()
        .ok()?
        .split(';')
        .filter_map(|part| part.trim().split_once('='))
        .find(|(k, _)| *k == name)
        .map(|(_, v)| v.to_owned())
}

/// True when the request carries a live session cookie.
pub fn authed(app: &App, headers: &HeaderMap) -> bool {
    cookie_value(headers, COOKIE).is_some_and(|token| app.db.session_valid(&sha256(&token)))
}

fn set_cookie(name: &str, value: &str, max_age: i64, secure: bool) -> String {
    let mut cookie = format!("{name}={value}; HttpOnly; SameSite=Lax; Path=/; Max-Age={max_age}");
    if secure {
        cookie.push_str("; Secure");
    }
    cookie
}

/// Digest of the caller's own session, so a session list can mark it.
pub fn current_session(headers: &HeaderMap) -> Option<String> {
    cookie_value(headers, COOKIE).map(|token| sha256(&token))
}

/// When a session with this expiry was issued. `issue_session` sets the expiry
/// to the issue time plus `SESSION_DAYS`, so this is exact rather than an
/// estimate; the two move together.
pub fn issued_at(expires_at: i64) -> i64 {
    expires_at - SESSION_DAYS * 86_400
}

/// The request's headers decide the Secure flag when the hub has no `--site`;
/// see `App::secure_cookies`.
pub fn issue_session(app: &App, headers: &HeaderMap) -> Result<String> {
    let token = random_token();
    app.db.create_session(&sha256(&token), Utc::now().timestamp() + SESSION_DAYS * 86_400)?;
    Ok(set_cookie(COOKIE, &token, SESSION_DAYS * 86_400, app.secure_cookies(headers)))
}

#[derive(Deserialize)]
pub struct LoginBody {
    password: String,
}

pub async fn login(
    State(app): State<crate::Shared>,
    ConnectInfo(peer): ConnectInfo<std::net::SocketAddr>,
    headers: HeaderMap,
    Json(body): Json<LoginBody>,
) -> Response {
    let ip = client_ip(&app.trusted_proxies, &headers, peer.ip());
    if app.throttle.locked(ip) {
        return (StatusCode::TOO_MANY_REQUESTS, "too many attempts, try again later").into_response();
    }
    // Held across the check below, which is its purpose.
    let Ok(_permit) = PASSWORD_GATE.try_acquire() else {
        return (StatusCode::TOO_MANY_REQUESTS, "too many attempts, try again later").into_response();
    };
    let Some(stored) = app.db.get("admin_password_hash") else {
        return (StatusCode::FORBIDDEN, "password login is disabled").into_response();
    };
    if !verify_password(&body.password, &stored) {
        app.throttle.record_failure(ip);
        return (StatusCode::UNAUTHORIZED, "invalid password").into_response();
    }
    app.throttle.clear(ip);
    match issue_session(&app, &headers) {
        Ok(cookie) => with_cookies(Json(serde_json::json!({"ok": true})), [cookie]),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

pub async fn logout(State(app): State<crate::Shared>, headers: HeaderMap) -> Response {
    if let Some(token) = cookie_value(&headers, COOKIE) {
        let _ = app.db.drop_session(&sha256(&token));
    }
    with_cookies(
        Json(serde_json::json!({"ok": true})),
        [set_cookie(COOKIE, "", 0, app.secure_cookies(&headers))],
    )
}

/// Step one of the OAuth exchange: issue a state nonce and redirect the browser
/// to GitHub. The nonce returns in step two and must match.
pub async fn github_start(State(app): State<crate::Shared>, headers: HeaderMap) -> Response {
    let Some(client_id) = app.db.get("github_client_id").filter(|v| !v.is_empty()) else {
        return (StatusCode::PRECONDITION_FAILED, "GitHub sign-in is not configured").into_response();
    };
    let state = random_token();
    let url = format!(
        "https://github.com/login/oauth/authorize?client_id={client_id}&scope=read:user&state={state}"
    );
    with_cookies(Redirect::to(&url), [set_cookie(STATE_COOKIE, &state, 600, app.secure_cookies(&headers))])
}

/// Every field is optional. With required fields axum would reject a malformed
/// callback before the handler runs, returning a bare 400 and logging nothing;
/// GitHub also reports a refusal with `error` and no `code`.
#[derive(Deserialize, Default)]
pub struct Callback {
    #[serde(default)]
    code: Option<String>,
    #[serde(default)]
    state: Option<String>,
    #[serde(default)]
    error: Option<String>,
    #[serde(default)]
    error_description: Option<String>,
}

pub async fn github_callback(
    State(app): State<crate::Shared>,
    headers: HeaderMap,
    Query(query): Query<Callback>,
) -> Response {
    // GitHub reports a refusal in the query string rather than the body.
    if let Some(error) = &query.error {
        let reason = query.error_description.as_deref().unwrap_or(error);
        return sign_in_failed(&app, &headers, &format!("GitHub returned {error}: {reason}"));
    }
    // Reject a callback the browser did not initiate.
    let state = query.state.as_deref().unwrap_or_default();
    if state.is_empty() || cookie_value(&headers, STATE_COOKIE).as_deref() != Some(state) {
        return sign_in_failed(
            &app,
            &headers,
            "state mismatch or missing; start again from the sign-in page",
        );
    }
    let Some(code) = query.code.as_deref().filter(|c| !c.is_empty()) else {
        return sign_in_failed(&app, &headers, "GitHub sent no authorization code");
    };
    if let Err(e) = github_login(&app, code).await {
        return sign_in_failed(&app, &headers, &e.to_string());
    }
    let session = match issue_session(&app, &headers) {
        Ok(cookie) => cookie,
        Err(e) => return sign_in_failed(&app, &headers, &e.to_string()),
    };
    with_cookies(Redirect::to("/admin"), [clear_state(&app, &headers), session])
}

/// Redirects the browser back to the sign-in page with the reason, rather than
/// leaving a bare 401 at a callback URL offering no way forward.
fn sign_in_failed(app: &App, headers: &HeaderMap, reason: &str) -> Response {
    // A rejected sign-in must leave a server-side record; the browser sees only
    // the redirect.
    warn!("GitHub sign-in rejected: {reason}");
    let target = format!("/admin?login_error={}", urlencode(reason));
    with_cookies(Redirect::to(&target), [clear_state(app, headers), String::new()])
}

fn clear_state(app: &App, headers: &HeaderMap) -> String {
    set_cookie(STATE_COOKIE, "", 0, app.secure_cookies(headers))
}

/// Attaches several `Set-Cookie` headers to one response. An array of header
/// tuples is unsuitable: axum applies those with `HeaderMap::insert`, so a
/// second `Set-Cookie` replaces the first. Empty entries are skipped.
pub fn with_cookies<const N: usize>(response: impl IntoResponse, cookies: [String; N]) -> Response {
    let mut response = response.into_response();
    for cookie in cookies {
        if cookie.is_empty() {
            continue;
        }
        match cookie.parse() {
            Ok(value) => {
                response.headers_mut().append(header::SET_COOKIE, value);
            }
            Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, "bad cookie").into_response(),
        }
    }
    response
}

/// Percent-encodes everything outside the unreserved set, sufficient for
/// placing an arbitrary message in a query string.
fn urlencode(value: &str) -> String {
    value
        .bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => (b as char).to_string(),
            _ => format!("%{b:02X}"),
        })
        .collect()
}

/// Exchanges the code for a token and checks the login against the allow list.
async fn github_login(app: &App, code: &str) -> Result<()> {
    let (Some(id), Some(secret)) = (app.db.get("github_client_id"), app.db.get("github_client_secret"))
    else {
        bail!("not configured");
    };
    let allowed = app.db.get("github_allowed_users").unwrap_or_default();
    let allowed: Vec<String> =
        allowed.split(',').map(|s| s.trim().to_lowercase()).filter(|s| !s.is_empty()).collect();
    if allowed.is_empty() {
        // Without an allow list, any GitHub account could sign in.
        bail!("no allowed GitHub users configured");
    }

    #[derive(Deserialize)]
    struct TokenResponse {
        access_token: Option<String>,
        error_description: Option<String>,
    }
    let token: TokenResponse = app
        .http
        .post("https://github.com/login/oauth/access_token")
        .header(header::ACCEPT, "application/json")
        .json(&serde_json::json!({"client_id": id, "client_secret": secret, "code": code}))
        .send()
        .await
        .context("token request")?
        .json()
        .await
        .context("token response")?;
    let Some(access) = token.access_token else {
        bail!("{}", token.error_description.unwrap_or_else(|| "no access token".into()));
    };

    #[derive(Deserialize)]
    struct GithubUser {
        login: String,
    }
    let response = app
        .http
        .get("https://api.github.com/user")
        .header(header::AUTHORIZATION, format!("Bearer {access}"))
        .header(header::USER_AGENT, "monitor-hub")
        .send()
        .await
        .context("user request")?;
    let status = response.status();
    let body = response.text().await.context("user response")?;
    // Decoding an error page into GithubUser would report "missing field login"
    // instead of GitHub's actual message.
    let user: GithubUser = serde_json::from_str(&body).with_context(|| {
        format!("user response ({status}): {}", body.chars().take(200).collect::<String>())
    })?;

    if !allowed.contains(&user.login.to_lowercase()) {
        // The list stays in the log and out of the reason, which travels back in
        // a query string: any GitHub account can reach that page, and a reason
        // carrying the allow list would disclose the accounts worth phishing.
        warn!("GitHub user {} is not on the allowed list {allowed:?}", user.login);
        bail!("GitHub user {} is not on the allowed list", user.login);
    }
    info!("GitHub sign-in accepted for {}", user.login);
    Ok(())
}

/// Peer address, or the last hop in X-Forwarded-For when the request arrived
/// through a proxy named in `trust`. Used for throttling and for the address
/// shown beside a node, never for authorization.
///
/// The header is honoured only from a peer in `trust`; see [`TrustedProxies`] for
/// why that is a list rather than a guess about the network. An untrusted peer
/// gets nothing from it: honoured, the header would let a caller mint a fresh
/// identity per request, bypassing the lockout and growing the throttle map
/// without bound.
///
/// The last value is taken, not the first. Both documented proxies append
/// rather than replace -- nginx's `$proxy_add_x_forwarded_for`, caddy's
/// `reverse_proxy` default -- so a caller supplying its own `X-Forwarded-For`
/// leaves that value at the head while the address the proxy observed lands at
/// the tail. Reading the head would return control of the lockout to the
/// caller: rotating the header makes every attempt a fresh address, and writing
/// the operator's address locks them out of the sign-in page.
///
/// A second trusted proxy in front of the first places its own address at the
/// tail instead. No single value in this header identifies the client, so
/// such a deployment must have its edge write the client address.
///
/// Both addresses are canonicalized. The default dual-stack `[::]` listener
/// reports IPv4 peers, 127.0.0.1 included, as `::ffff:a.b.c.d`; without this a
/// loopback proxy would arrive looking like a v6 address that no v4 entry of
/// the list matches.
pub fn client_ip(trust: &TrustedProxies, headers: &HeaderMap, peer: IpAddr) -> IpAddr {
    let peer = peer.to_canonical();
    if !trust.contains(peer) {
        return peer;
    }
    headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.rsplit(',').next())
        .and_then(|v| v.trim().parse::<IpAddr>().ok())
        .map_or(peer, |ip| ip.to_canonical())
}

/// Which peers may set `X-Forwarded-For` on a caller's behalf.
///
/// A list rather than a guess about the network. This used to accept the header
/// from any private address, reading "private" as "a reverse proxy of ours". It
/// is not: it is every other machine on the LAN, on the VPN, and in the
/// neighbouring container. Since `--listen` defaults to a wildcard, any of them
/// could reach the port directly and mint a fresh client address per request,
/// which is the whole of the sign-in lockout -- [`Throttle`] counts failures per
/// address, so a caller free to choose its address is free to keep guessing.
///
/// Loopback is always trusted, which is the deployment `install-hub.sh` sets up:
/// the proxy runs on this host and connects over 127.0.0.1. A proxy anywhere else
/// has to be named, because nothing about its address says it is a proxy rather
/// than a caller.
#[derive(Clone, Debug)]
pub struct TrustedProxies(Vec<Trusted>);

/// One entry: an address, and how much of it has to match.
#[derive(Clone, Copy, Debug)]
struct Trusted {
    addr: IpAddr,
    bits: u8,
}

impl Default for TrustedProxies {
    fn default() -> Self {
        Self::loopback()
    }
}

impl TrustedProxies {
    pub fn loopback() -> Self {
        Self(vec![
            Trusted { addr: IpAddr::V4(Ipv4Addr::LOCALHOST), bits: 8 },
            Trusted { addr: IpAddr::V6(Ipv6Addr::LOCALHOST), bits: 128 },
        ])
    }

    /// Loopback, plus whatever `--trusted-proxy` names.
    ///
    /// Loopback is never dropped. A process on this host can read the database
    /// outright, so believing it about a header grants nothing it did not already
    /// have -- while a local proxy that silently stopped being trusted would
    /// collapse every caller behind it into one throttle bucket, locking all of
    /// them out the moment anyone mistypes a password five times.
    ///
    /// A spec that does not parse is an error rather than a skip: silently
    /// trusting nobody, or somebody else, is exactly the change this list exists
    /// to make visible.
    pub fn from_specs<I: IntoIterator<Item = String>>(specs: I) -> Result<Self> {
        let mut list = Self::loopback();
        for spec in specs {
            list.0.push(Trusted::parse(&spec)?);
        }
        Ok(list)
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        self.0.iter().any(|t| t.contains(ip))
    }
}

impl std::fmt::Display for TrustedProxies {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let entries: Vec<String> = self.0.iter().map(|t| format!("{}/{}", t.addr, t.bits)).collect();
        f.write_str(&entries.join(", "))
    }
}

/// Whether the first `bits` bits of two addresses agree. Slices rather than
/// `Ipv4Addr`/`Ipv6Addr` because the arithmetic is the same for 32 bits and for
/// 128, and one implementation is one place to go wrong.
fn same_prefix(net: &[u8], got: &[u8], bits: u8) -> bool {
    let whole = (bits / 8) as usize;
    let rest = bits % 8;
    // `rest == 0` short-circuits, so the partial byte is read only when there is
    // one to read -- at 32 and 128 bits `whole` is already past the last byte.
    net[..whole] == got[..whole] && (rest == 0 || (net[whole] >> (8 - rest)) == (got[whole] >> (8 - rest)))
}

impl Trusted {
    fn parse(spec: &str) -> Result<Self> {
        let spec = spec.trim();
        let (addr, len) = match spec.split_once('/') {
            Some((addr, len)) => (addr, Some(len)),
            None => (spec, None),
        };
        let addr: IpAddr = addr.parse().with_context(|| {
            format!("--trusted-proxy {spec:?} is not an address or a CIDR block, e.g. 10.0.0.0/8 or ::1")
        })?;
        let max = if addr.is_ipv4() { 32 } else { 128 };
        let bits = match len {
            Some(len) => len
                .trim()
                .parse::<u8>()
                .with_context(|| format!("--trusted-proxy {spec:?} has an unreadable prefix length"))?,
            None => max,
        };
        if bits > max {
            bail!("--trusted-proxy {spec:?} has a longer prefix than the {max} bits of its address");
        }
        // A zero-length prefix is every address there is, which would put the header
        // back under the caller's control -- the arrangement this list replaced.
        // Nothing is a proxy at every address.
        if bits == 0 {
            bail!("--trusted-proxy {spec:?} would trust every caller; a proxy has an address");
        }
        // A v4-mapped entry can never match: the peer is canonicalized to its v4
        // form before it is compared, so this is a trust entry that looks applied
        // and does nothing.
        if let IpAddr::V6(v6) = addr {
            if let Some(v4) = v6.to_ipv4_mapped() {
                bail!("--trusted-proxy {spec:?} is {v4} in v6 form; name it as a v4 address");
            }
        }
        Ok(Self { addr, bits })
    }

    fn contains(&self, ip: IpAddr) -> bool {
        match (self.addr, ip) {
            (IpAddr::V4(net), IpAddr::V4(got)) => same_prefix(&net.octets(), &got.octets(), self.bits),
            (IpAddr::V6(net), IpAddr::V6(got)) => same_prefix(&net.octets(), &got.octets(), self.bits),
            // Different families. The caller canonicalizes first, so this pairs an
            // entry with a genuinely other address rather than with the v4-mapped
            // form of a v4 one.
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_password_round_trips_fails_closed_and_never_repeats_a_salt() {
        let hash = hash_password("correct horse battery staple").unwrap();
        assert!(verify_password("correct horse battery staple", &hash));
        assert!(!verify_password("Correct horse battery staple", &hash));
        assert!(!verify_password("", &hash));
        // A corrupt or empty stored hash must fail closed.
        assert!(!verify_password("anything", "not-a-hash"));
        assert!(!verify_password("anything", ""));
        // The salt is per hash, so cracking one row does not reveal every other
        // row sharing that password.
        assert_ne!(hash_password("same").unwrap(), hash_password("same").unwrap());
    }

    /// One address through the full lockout lifecycle: attempts up to the limit
    /// are allowed, the next locks the address out, the window expires on its
    /// own, and a success clears it early. The window is shortened so expiry is
    /// reachable within the test.
    #[test]
    fn a_lockout_lands_expires_on_its_own_and_clears_on_success() {
        let window = Duration::from_millis(60);
        let t = Throttle { window, ..Default::default() };
        let ip: IpAddr = "203.0.113.7".parse().unwrap();
        let other: IpAddr = "203.0.113.8".parse().unwrap();
        let stale: IpAddr = "203.0.113.9".parse().unwrap();
        let held = || t.seen.lock().unwrap().len();

        t.record_failure(stale);
        for _ in 0..MAX_ATTEMPTS {
            assert!(!t.locked(ip), "attempts up to the limit are still allowed");
            t.record_failure(ip);
        }
        assert!(t.locked(ip), "the attempt past the limit is shut out");
        assert!(!t.locked(other), "the lockout must not spread to other addresses");

        // A lockout is a delay rather than a ban: the address is readmitted
        // automatically.
        std::thread::sleep(window * 2);
        assert!(!t.locked(ip), "an expired lockout must lift on its own");

        // `stale` is never queried, so only the sweep on entry can remove it.
        // Without it the map grows by one entry per address presented, for the
        // life of the process.
        assert_eq!(held(), 1, "the expired lockout is gone, stale is still held");
        t.record_failure(other);
        assert_eq!(held(), 1, "the stale address is swept, not carried");

        // A correct password clears the count, so two typos do not make the next
        // mistake a lockout.
        t.clear(other);
        assert_eq!(held(), 0);
    }

    /// The gate must refuse rather than queue: a queue admits the same flood,
    /// and each attempt that lands costs 19 MiB which remains in a thread's
    /// arena for the life of the process.
    #[test]
    fn the_password_gate_refuses_a_flood_rather_than_queueing_it() {
        let held: Vec<_> =
            (0..PASSWORD_CHECKS).map(|_| PASSWORD_GATE.try_acquire().expect("up to the limit")).collect();
        assert!(PASSWORD_GATE.try_acquire().is_err(), "the attempt past the limit must be refused");
        drop(held);
        assert!(PASSWORD_GATE.try_acquire().is_ok(), "permits come back when the checks finish");
    }

    /// Both ends of the same redirect: every form GitHub can send must parse,
    /// or it never reaches the handler and can be neither logged nor explained,
    /// and the reason sent back must survive its query string.
    #[test]
    fn every_callback_shape_parses_and_a_failure_reason_survives_the_round_trip() {
        let parse = |q: &str| serde_urlencoded::from_str::<Callback>(q);

        let ok = parse("code=abc&state=xyz").expect("the happy path");
        assert_eq!(ok.code.as_deref(), Some("abc"));
        assert_eq!(ok.state.as_deref(), Some("xyz"));

        // GitHub reports a refusal with no code.
        let denied = parse("error=access_denied&error_description=the+user+said+no&state=xyz")
            .expect("a refusal must parse, not 400");
        assert_eq!(denied.error.as_deref(), Some("access_denied"));
        assert_eq!(denied.error_description.as_deref(), Some("the user said no"));
        assert!(denied.code.is_none());

        // Truncated or empty callbacks must still reach the handler.
        assert!(parse("state=xyz").is_ok());
        assert!(parse("").is_ok());

        // Anything that would escape the query string must be encoded, or the
        // reason arrives truncated at the first stray separator.
        assert_eq!(urlencode("a&b=c#d"), "a%26b%3Dc%23d");
        assert_eq!(urlencode("用户"), "%E7%94%A8%E6%88%B7");
        let reason = "no allowed GitHub users configured (a&b=c)";
        let back = parse(&format!("error={}", urlencode(reason))).expect("a reason must parse");
        assert_eq!(back.error.as_deref(), Some(reason), "the whole reason comes back");
    }

    /// A session cookie's round trip: the flags it is issued with, sharing a
    /// response with a second cookie, and being extracted from the single header
    /// the browser returns them in.
    #[test]
    fn a_session_cookie_goes_out_locked_down_alongside_others_and_parses_back() {
        let session = set_cookie(COOKIE, "abc123", 3_600, true);
        assert!(session.contains("HttpOnly") && session.contains("SameSite=Lax"));
        assert!(session.contains("Secure"));
        assert!(!set_cookie(COOKIE, "abc123", 3_600, false).contains("Secure"));

        // axum applies an array of header tuples with insert(), keeping only the
        // last Set-Cookie; this helper appends instead.
        let response = with_cookies(StatusCode::OK, [session, set_cookie(STATE_COOKIE, "s", 0, true)]);
        let set: Vec<_> = response.headers().get_all(header::SET_COOKIE).iter().collect();
        assert_eq!(set.len(), 2, "both cookies must reach the browser");
        // Empty entries are skipped rather than emitting a blank header.
        let response = with_cookies(StatusCode::OK, ["a=1".to_owned(), String::new()]);
        assert_eq!(response.headers().get_all(header::SET_COOKIE).iter().count(), 1);

        // And back: the browser returns them all in a single header.
        let mut h = HeaderMap::new();
        h.insert(header::COOKIE, "other=1; monitor_session=abc123; x=2".parse().unwrap());
        assert_eq!(cookie_value(&h, COOKIE).as_deref(), Some("abc123"));
        assert_eq!(cookie_value(&h, "missing"), None);
        assert_eq!(cookie_value(&HeaderMap::new(), COOKIE), None);
    }

    #[test]
    fn forwarded_header_is_trusted_only_from_a_named_proxy() {
        let ip = |s: &str| s.parse::<IpAddr>().unwrap();
        let xff = |v: &str| {
            let mut h = HeaderMap::new();
            h.insert("x-forwarded-for", v.parse().unwrap());
            h
        };
        // The default, which is what an unconfigured hub has.
        let trust = TrustedProxies::loopback();

        // Nothing arrived with the request: the proxy appended the single
        // address it observed, which is the entire header.
        assert_eq!(client_ip(&trust, &xff("198.51.100.9"), ip("127.0.0.1")).to_string(), "198.51.100.9");

        // The caller supplied a header of its own. Both documented proxies
        // append, so the fabricated value sits at the head and the proxy's
        // observation at the tail; reading the head would let a caller choose its
        // own throttle bucket each request, or claim the operator's address.
        let forged = xff("10.0.0.2, 198.51.100.9");
        for peer in ["127.0.0.1", "::1", "::ffff:127.0.0.1"] {
            assert_eq!(client_ip(&trust, &forged, ip(peer)).to_string(), "198.51.100.9", "{peer}");
        }

        // A dual-stack `[::]` listener reports an IPv4 proxy as `::ffff:a.b.c.d`,
        // which is the same loopback peer.
        assert_eq!(client_ip(&trust, &HeaderMap::new(), ip("::ffff:203.0.113.5")), ip("203.0.113.5"));

        // Directly from the internet the entire header is caller-supplied, and
        // honouring any part of it bypasses the lockout.
        assert_eq!(client_ip(&trust, &forged, ip("203.0.113.5")), ip("203.0.113.5"));
        assert_eq!(client_ip(&trust, &forged, ip("2001:db8::5")), ip("2001:db8::5"));
    }

    /// A private address is not a proxy. It was believed as one, so any machine on
    /// the LAN -- or the VPN, or the neighbouring container -- could pick its own
    /// throttle bucket per request, and with `--listen` at its wildcard default it
    /// could reach the port to do it.
    #[test]
    fn a_private_address_has_to_be_named_to_speak_for_the_caller() {
        let ip = |s: &str| s.parse::<IpAddr>().unwrap();
        let mut h = HeaderMap::new();
        h.insert("x-forwarded-for", "198.51.100.9".parse().unwrap());

        let trust = TrustedProxies::loopback();
        for peer in ["10.0.0.1", "192.168.1.5", "172.18.0.4", "fd00::1"] {
            assert_eq!(client_ip(&trust, &h, ip(peer)), ip(peer), "{peer} is not a proxy by position");
        }
        // The dual-stack listener reports an IPv4 peer as `::ffff:a.b.c.d`. The
        // same address in another spelling, still not a proxy, and canonicalized
        // before it is compared -- without that no v4 entry would ever match the
        // loopback proxy.
        assert_eq!(client_ip(&trust, &h, ip("::ffff:172.18.0.4")), ip("172.18.0.4"));

        // Named, the same header from the same peer is believed -- and loopback
        // stays in the list without being named.
        let named = TrustedProxies::from_specs(["172.18.0.0/16".to_string()]).unwrap();
        assert_eq!(client_ip(&named, &h, ip("172.18.0.4")).to_string(), "198.51.100.9");
        assert_eq!(client_ip(&named, &h, ip("127.0.0.1")).to_string(), "198.51.100.9");
        assert_eq!(client_ip(&named, &h, ip("10.0.0.1")), ip("10.0.0.1"), "a block not named is still not");
    }

    #[test]
    fn a_trusted_proxy_spec_is_an_address_or_a_block() {
        let have = |spec: &str, peer: &str| {
            let trust = TrustedProxies::from_specs([spec.to_string()]).unwrap();
            trust.contains(peer.parse::<IpAddr>().unwrap())
        };

        // A bare address is a block of one, and each family is compared to its own
        // width.
        assert!(have("10.0.0.1", "10.0.0.1") && !have("10.0.0.1", "10.0.0.2"));
        assert!(have("10.0.0.0/8", "10.255.255.255") && !have("10.0.0.0/8", "11.0.0.0"));
        assert!(have("2001:db8::/32", "2001:db8:ffff::1") && !have("2001:db8::/32", "2001:db9::1"));
        // A prefix that is not a whole number of bytes: the partial byte is the one
        // most likely to be compared wrongly.
        assert!(have("192.168.1.128/25", "192.168.1.255") && !have("192.168.1.128/25", "192.168.1.127"));
        assert!(have("2001:db8::/33", "2001:db8:7fff::1") && !have("2001:db8::/33", "2001:db8:8000::1"));
        // Full length, where the comparison must not read past the last byte.
        assert!(have("10.0.0.1/32", "10.0.0.1") && have("::1/128", "::1"));
        // Families do not mix.
        assert!(!have("10.0.0.0/8", "2001:db8::1") && !have("2001:db8::/32", "203.0.113.9"));
        // A spec that does not parse is an error rather than a silent skip: this
        // list is the whole of who may set the client address. So is one that parses
        // and then trusts every caller, and one that parses into an address a peer
        // can never arrive as.
        for bad in [
            "",
            "   ",
            "not-an-address",
            "10.0.0.0/33",
            "::1/129",
            "10.0.0.0/x",
            "10.0.0.0/",
            "10.0.0.1:80",
            "0.0.0.0/0",
            "::/0",
            "::ffff:10.0.0.1/96",
        ] {
            assert!(TrustedProxies::from_specs([bad.to_string()]).is_err(), "{bad}");
        }
    }
}
