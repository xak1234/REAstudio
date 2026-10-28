//! Single-use native close handshake. Missing or stale UI replies never discard work.
use serde::Deserialize;
use std::time::{Duration, Instant};
use uuid::Uuid;

pub const ACK_TIMEOUT: Duration = Duration::from_secs(5);
pub const DECISION_TIMEOUT: Duration = Duration::from_secs(10 * 60);
const MAX_MESSAGE_BYTES: usize = 512;

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Decision {
    Close,
    Cancel,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", deny_unknown_fields)]
pub enum Message {
    #[serde(rename = "rea-close-ready")]
    Ready { nonce: String },
    #[serde(rename = "rea-close-response")]
    Response { nonce: String, action: Decision },
}

impl Message {
    fn nonce(&self) -> &str {
        match self {
            Self::Ready { nonce } | Self::Response { nonce, .. } => nonce,
        }
    }
}

/// Wry supplies the actual WebView message source, not a URL from the JSON body.
pub fn parse_message(source: &str, body: &str) -> Option<Message> {
    if body.len() > MAX_MESSAGE_BYTES || !trusted_page(source) {
        return None;
    }
    let message: Message = serde_json::from_str(body).ok()?;
    let nonce = message.nonce();
    if nonce.len() != 36 || Uuid::parse_str(nonce).ok()?.to_string() != nonce {
        return None;
    }
    Some(message)
}

fn trusted_page(source: &str) -> bool {
    let Ok(url) = url::Url::parse(source) else {
        return false;
    };
    url.username().is_empty()
        && url.password().is_none()
        && url.port().is_none()
        && matches!(url.path(), "/" | "/playground" | "/playground/")
        && ((url.scheme() == "app" && url.host_str() == Some("localhost"))
            || (url.scheme() == "http" && url.host_str() == Some("app.localhost")))
}

struct Pending {
    nonce: String,
    started: Instant,
    acknowledged: bool,
}

impl Pending {
    fn deadline(&self) -> Instant {
        self.started
            + if self.acknowledged {
                DECISION_TIMEOUT
            } else {
                ACK_TIMEOUT
            }
    }
}

#[derive(Default)]
enum State {
    #[default]
    Idle,
    Pending(Pending),
    NativeFallback {
        nonce: String,
        valid: bool,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExpiryReason {
    Unresponsive,
    DecisionExpired,
}

pub struct Expired {
    pub nonce: String,
    pub reason: ExpiryReason,
}

#[derive(Default)]
pub struct CloseGuard {
    state: State,
}

impl CloseGuard {
    /// Repeated clicks reuse the request and never extend either deadline.
    /// A native confirmation owns the close decision until it returns.
    pub fn begin(&mut self, now: Instant) -> Option<String> {
        match &self.state {
            State::Pending(pending) if now < pending.deadline() => {
                return Some(pending.nonce.clone());
            }
            State::NativeFallback { .. } => return None,
            _ => {}
        }
        let nonce = Uuid::new_v4().to_string();
        self.state = State::Pending(Pending {
            nonce: nonce.clone(),
            started: now,
            acknowledged: false,
        });
        Some(nonce)
    }

    pub fn receive(&mut self, message: Message, now: Instant) -> Option<Decision> {
        let State::Pending(pending) = &mut self.state else {
            return None;
        };
        if pending.nonce != message.nonce() || now >= pending.deadline() {
            return None;
        }
        match message {
            Message::Ready { .. } => {
                pending.acknowledged = true;
                None
            }
            Message::Response { action, .. } if pending.acknowledged => {
                self.state = State::Idle;
                Some(action)
            }
            Message::Response { .. } => None,
        }
    }

    pub fn deadline(&self) -> Option<Instant> {
        match &self.state {
            State::Pending(pending) => Some(pending.deadline()),
            _ => None,
        }
    }

    pub fn expire(&mut self, now: Instant) -> Option<Expired> {
        let State::Pending(pending) = &self.state else {
            return None;
        };
        if now < pending.deadline() {
            return None;
        }
        let expired = Expired {
            nonce: pending.nonce.clone(),
            reason: if pending.acknowledged {
                ExpiryReason::DecisionExpired
            } else {
                ExpiryReason::Unresponsive
            },
        };
        self.state = State::Idle;
        Some(expired)
    }

    /// Reload/navigation invalidates all previously displayed close decisions.
    /// A native dialog remains the sole dialog until its stale result returns.
    pub fn invalidate(&mut self) -> Option<String> {
        match &mut self.state {
            State::Pending(pending) => {
                let nonce = pending.nonce.clone();
                self.state = State::Idle;
                Some(nonce)
            }
            State::NativeFallback { valid, .. } => {
                *valid = false;
                None
            }
            State::Idle => None,
        }
    }

    pub fn begin_fallback(&mut self) -> Option<String> {
        if !matches!(self.state, State::Idle) {
            return None;
        }
        let nonce = Uuid::new_v4().to_string();
        self.state = State::NativeFallback {
            nonce: nonce.clone(),
            valid: true,
        };
        Some(nonce)
    }

    pub fn finish_fallback(&mut self, nonce: &str, close: bool) -> Option<Decision> {
        let State::NativeFallback {
            nonce: active,
            valid,
        } = &self.state
        else {
            return None;
        };
        if active != nonce {
            return None;
        }
        let decision = if *valid && close {
            Decision::Close
        } else {
            Decision::Cancel
        };
        self.state = State::Idle;
        Some(decision)
    }
}

pub fn request_script(nonce: &str, active_work: bool) -> String {
    event_script(
        "rea-native-close-request",
        serde_json::json!({ "nonce": nonce, "activeWork": active_work }),
    )
}

pub fn cancelled_script(nonce: &str, reason: &str) -> String {
    event_script(
        "rea-native-close-cancelled",
        serde_json::json!({ "nonce": nonce, "reason": reason }),
    )
}

fn event_script(name: &str, detail: serde_json::Value) -> String {
    // Both event names are constants; serializing detail avoids script interpolation.
    format!(
        "window.dispatchEvent(new CustomEvent({}, {{detail:{}}}));",
        serde_json::to_string(name).expect("a constant event name serializes"),
        detail
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ready(nonce: &str) -> Message {
        Message::Ready {
            nonce: nonce.into(),
        }
    }
    fn answer(nonce: &str, action: Decision) -> Message {
        Message::Response {
            nonce: nonce.into(),
            action,
        }
    }

    #[test]
    fn only_the_owned_page_and_bounded_exact_messages_are_accepted() {
        let nonce = Uuid::new_v4().to_string();
        let body = serde_json::json!({"type":"rea-close-response","nonce":nonce,"action":"close"})
            .to_string();
        for page in [
            "app://localhost/playground",
            "http://app.localhost/playground/",
            "app://localhost/",
        ] {
            assert!(parse_message(page, &body).is_some(), "{page}");
        }
        for page in [
            "https://app.localhost/playground",
            "http://app.localhost.evil/playground",
            "app://localhost/api/quixi/playground/state",
            "http://user@app.localhost/playground",
            "http://app.localhost:9999/playground",
            "file:///playground",
        ] {
            assert!(parse_message(page, &body).is_none(), "{page}");
        }
        let extra = serde_json::json!({"type":"rea-close-response","nonce":nonce,"action":"close","url":"app://localhost/playground"}).to_string();
        assert!(parse_message("app://localhost/playground", &extra).is_none());
        assert!(parse_message("app://localhost/playground", &"x".repeat(513)).is_none());
        assert!(parse_message(
            "app://localhost/playground",
            r#"{"type":"rea-close-response","nonce":"x","action":"close"}"#
        )
        .is_none());
        assert!(parse_message(
            "app://localhost/playground",
            &body.replace("\"close\"", "\"discard\"")
        )
        .is_none());
    }

    #[test]
    fn close_requires_ready_and_an_active_single_use_nonce() {
        let now = Instant::now();
        let mut guard = CloseGuard::default();
        assert_eq!(guard.receive(answer("unused", Decision::Close), now), None);
        let nonce = guard.begin(now).unwrap();
        assert_eq!(guard.receive(answer(&nonce, Decision::Close), now), None);
        assert_eq!(guard.receive(ready(&Uuid::new_v4().to_string()), now), None);
        assert_eq!(guard.deadline(), Some(now + ACK_TIMEOUT));
        assert_eq!(guard.receive(ready(&nonce), now), None);
        assert_eq!(
            guard.receive(answer(&nonce, Decision::Close), now),
            Some(Decision::Close)
        );
        assert_eq!(guard.receive(answer(&nonce, Decision::Close), now), None);
        let next = guard.begin(now).unwrap();
        assert_ne!(nonce, next);
        assert_eq!(guard.receive(answer(&nonce, Decision::Close), now), None);
    }

    #[test]
    fn repeated_clicks_or_ready_messages_never_extend_deadlines() {
        let now = Instant::now();
        let mut guard = CloseGuard::default();
        let nonce = guard.begin(now).unwrap();
        assert_eq!(
            guard.begin(now + Duration::from_secs(4)).as_deref(),
            Some(nonce.as_str())
        );
        assert_eq!(guard.deadline(), Some(now + ACK_TIMEOUT));
        let _ = guard.receive(ready(&nonce), now + Duration::from_secs(4));
        assert_eq!(guard.deadline(), Some(now + DECISION_TIMEOUT));
        let _ = guard.receive(ready(&nonce), now + Duration::from_secs(500));
        assert_eq!(guard.deadline(), Some(now + DECISION_TIMEOUT));
        let expired = guard.expire(now + DECISION_TIMEOUT).unwrap();
        assert_eq!(expired.reason, ExpiryReason::DecisionExpired);
        assert_eq!(
            guard.receive(answer(&nonce, Decision::Close), now + DECISION_TIMEOUT),
            None
        );
    }

    #[test]
    fn missing_ack_cancel_and_reload_all_preserve_the_window() {
        let now = Instant::now();
        let mut guard = CloseGuard::default();
        let nonce = guard.begin(now).unwrap();
        let expired = guard.expire(now + ACK_TIMEOUT).unwrap();
        assert_eq!(expired.reason, ExpiryReason::Unresponsive);
        assert_eq!(guard.receive(ready(&nonce), now + ACK_TIMEOUT), None);
        let next = guard.begin(now + ACK_TIMEOUT).unwrap();
        let _ = guard.receive(ready(&next), now + ACK_TIMEOUT);
        assert_eq!(
            guard.receive(answer(&next, Decision::Cancel), now + ACK_TIMEOUT),
            Some(Decision::Cancel)
        );
        assert_eq!(
            guard.receive(answer(&next, Decision::Close), now + ACK_TIMEOUT),
            None
        );
        let reload = guard.begin(now + ACK_TIMEOUT).unwrap();
        let _ = guard.receive(ready(&reload), now + ACK_TIMEOUT);
        assert_eq!(guard.invalidate().as_deref(), Some(reload.as_str()));
        assert_eq!(
            guard.receive(answer(&reload, Decision::Close), now + ACK_TIMEOUT),
            None
        );
    }

    #[test]
    fn native_confirmation_is_exclusive_and_stale_choices_never_close() {
        let now = Instant::now();
        let mut guard = CloseGuard::default();
        let old = guard.begin(now).unwrap();
        let _ = guard.expire(now + ACK_TIMEOUT);
        let native = guard.begin_fallback().unwrap();
        assert!(guard.begin(now).is_none());
        assert!(guard.begin_fallback().is_none());
        assert_eq!(guard.receive(ready(&old), now), None);
        assert_eq!(guard.receive(answer(&old, Decision::Close), now), None);
        assert_eq!(guard.finish_fallback("wrong", true), None);
        let _ = guard.invalidate();
        assert!(guard.begin(now).is_none());
        assert_eq!(guard.finish_fallback(&native, true), Some(Decision::Cancel));
        assert_eq!(guard.finish_fallback(&native, true), None);
        let native = guard.begin_fallback().unwrap();
        assert_eq!(
            guard.finish_fallback(&native, false),
            Some(Decision::Cancel)
        );
        assert_eq!(guard.finish_fallback(&native, true), None);
        let native = guard.begin_fallback().unwrap();
        assert_eq!(guard.finish_fallback(&native, true), Some(Decision::Close));
    }
}
