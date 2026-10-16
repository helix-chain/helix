//! Rust client seam for the ML mismatch detector (v0.2, task B2 — Rust side).
//!
//! `mismatch_detector.py` is a DEPLOY-TIME source auditor: it consumes Solidity
//! source and returns a graded report. This client speaks the detector's JSON
//! wire schema over loopback HTTP to a future sidecar service (FastAPI wrapping
//! `analyze_contract`, keeping the codebert model warm — task B2 Python side).
//!
//! It is deliberately **advisory** and **fail-open**: if the sidecar is
//! unreachable or slow, a scan never blocks and never errors the caller — it
//! returns [`DetectorOutcome::Unavailable`]. This client is intentionally NOT a
//! [`crate::hook::SecurityHook`]: the detector needs source, which a runtime
//! transaction does not carry. Runtime defense is the deterministic
//! [`crate::immune::ImmuneHook`]; this is for the deploy / scan path.

use std::time::Duration;

use serde::Deserialize;

use crate::hook::RiskLevel;

/// One function-level finding in the detector's report.
#[derive(Debug, Clone, Deserialize)]
pub struct FunctionFinding {
    pub name: String,
    pub mismatch_score: f64,
    #[serde(default)]
    pub attack_class: Option<String>,
}

/// The detector's JSON report (mirrors `mismatch_detector.analyze_contract`).
/// Unknown fields (e.g. `contract_address`) are ignored, so the wire schema can
/// grow on the Python side without breaking this client.
#[derive(Debug, Clone, Deserialize)]
pub struct DetectorReport {
    pub risk_level: String,
    pub overall_mismatch_score: f64,
    #[serde(default)]
    pub recommended_action: String,
    pub functions: Vec<FunctionFinding>,
}

impl DetectorReport {
    /// Map the detector's textual risk level onto the shared [`RiskLevel`] grade.
    pub fn risk(&self) -> Option<RiskLevel> {
        match self.risk_level.to_ascii_uppercase().as_str() {
            "CRITICAL" => Some(RiskLevel::Critical),
            "HIGH" => Some(RiskLevel::High),
            "MEDIUM" => Some(RiskLevel::Medium),
            "LOW" => Some(RiskLevel::Low),
            _ => None,
        }
    }
}

/// Decode and validate one detector report without performing network I/O.
pub fn parse_report(body: &str) -> Result<DetectorReport, String> {
    let report: DetectorReport = serde_json::from_str(body).map_err(|error| {
        let message = error.to_string();
        if message.starts_with("missing field") || message.contains("number out of range") {
            format!("schema drift: {message}")
        } else {
            format!("decode: {message}")
        }
    })?;

    if report.risk().is_none() {
        return Err(format!(
            "schema drift: unrecognized risk_level {:?}",
            report.risk_level
        ));
    }

    validate_score("overall_mismatch_score", report.overall_mismatch_score)?;
    for finding in &report.functions {
        validate_score("function mismatch_score", finding.mismatch_score)?;
    }

    Ok(report)
}

fn validate_score(name: &str, score: f64) -> Result<(), String> {
    if !score.is_finite() || !(0.0..=1.0).contains(&score) {
        return Err(format!(
            "schema drift: {name} must be finite and in 0.0..=1.0, got {score}"
        ));
    }
    Ok(())
}

/// Result of a deploy-time scan. `Unavailable` is the fail-open outcome and
/// carries a reason for logging — it is never an error the caller must handle.
#[derive(Debug, Clone)]
pub enum DetectorOutcome {
    Scanned(DetectorReport),
    Unavailable(String),
}

/// Client for the deploy-time detector sidecar.
#[derive(Debug, Clone)]
pub struct DetectorClient {
    endpoint: String,
    timeout: Duration,
    http: reqwest::Client,
}

impl DetectorClient {
    /// `base_url` e.g. `"http://127.0.0.1:8600"`. Scans POST to `{base_url}/scan`.
    pub fn new(base_url: impl Into<String>, timeout: Duration) -> Self {
        let base = base_url.into();
        Self {
            endpoint: format!("{}/scan", base.trim_end_matches('/')),
            timeout,
            http: reqwest::Client::new(),
        }
    }

    /// Scan Solidity source. **Fail-open**: any transport / decode error becomes
    /// [`DetectorOutcome::Unavailable`], never an `Err`, so the caller's flow is
    /// never blocked by a missing or slow detector.
    pub async fn scan_source(&self, source: &str) -> DetectorOutcome {
        let sent = self
            .http
            .post(&self.endpoint)
            .timeout(self.timeout)
            .json(&serde_json::json!({ "source_code": source }))
            .send()
            .await;
        match sent {
            Ok(resp) => match resp.text().await {
                Ok(body) => match parse_report(&body) {
                    Ok(report) => DetectorOutcome::Scanned(report),
                    Err(message) => DetectorOutcome::Unavailable(message),
                },
                Err(e) => DetectorOutcome::Unavailable(format!("decode: {e}")),
            },
            Err(e) => DetectorOutcome::Unavailable(format!("transport: {e}")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_report_json(risk_level: &str) -> String {
        format!(
            r#"{{"contract_address":"0xabc","risk_level":"{risk_level}","overall_mismatch_score":0.95,"recommended_action":"review","functions":[{{"name":"withdraw","intent":"withdraw funds","code_behavior":"external call","mismatch_score":0.95,"attack_class":"reentrancy","evidence":"external call before state update","extra":1}}],"extra_top":true}}"#
        )
    }

    fn assert_schema_drift(body: &str) {
        let error = parse_report(body).expect_err("drifted report must be rejected");
        assert!(
            error.starts_with("schema drift:"),
            "expected schema drift reason, got {error:?}"
        );
    }

    #[test]
    fn report_maps_textual_risk_levels() {
        let mut r = DetectorReport {
            risk_level: "critical".into(),
            overall_mismatch_score: 0.9,
            recommended_action: String::new(),
            functions: vec![],
        };
        assert_eq!(r.risk(), Some(RiskLevel::Critical));
        r.risk_level = "HIGH".into();
        assert_eq!(r.risk(), Some(RiskLevel::High));
        r.risk_level = "LOW".into();
        assert_eq!(r.risk(), Some(RiskLevel::Low));
        r.risk_level = "anything-else".into();
        assert_eq!(r.risk(), None);
    }

    #[test]
    fn parse_report_accepts_valid_case_insensitive_risk_and_extra_fields() {
        let json = valid_report_json("critical");
        let report = parse_report(&json).expect("valid report decodes");
        assert_eq!(report.risk(), Some(RiskLevel::Critical));
        assert_eq!(report.functions.len(), 1);
        assert_eq!(report.functions[0].name, "withdraw");
    }

    #[test]
    fn parse_report_rejects_unknown_risk_labels() {
        for label in ["EXTREME", "anything-else"] {
            assert_schema_drift(&valid_report_json(label));
        }
    }

    #[test]
    fn parse_report_rejects_missing_required_function_score() {
        assert_schema_drift(
            r#"{"risk_level":"CRITICAL","overall_mismatch_score":0.95,"functions":[{"name":"withdraw"}]}"#,
        );
    }

    #[test]
    fn parse_report_rejects_renamed_overall_score_key() {
        assert_schema_drift(r#"{"risk_level":"CRITICAL","risk_score":0.95,"functions":[]}"#);
    }

    #[test]
    fn parse_report_rejects_missing_required_top_level_fields() {
        assert_schema_drift(r#"{"risk_level":"LOW","overall_mismatch_score":0.0}"#);
        assert_schema_drift(r#"{"overall_mismatch_score":0.0,"functions":[]}"#);
    }

    #[test]
    fn parse_report_rejects_out_of_range_scores() {
        for body in [
            r#"{"risk_level":"HIGH","overall_mismatch_score":1.5,"functions":[]}"#,
            r#"{"risk_level":"HIGH","overall_mismatch_score":-0.1,"functions":[]}"#,
            r#"{"risk_level":"HIGH","overall_mismatch_score":0.5,"functions":[{"name":"withdraw","mismatch_score":1.5}]}"#,
            r#"{"risk_level":"HIGH","overall_mismatch_score":0.5,"functions":[{"name":"withdraw","mismatch_score":-0.1}]}"#,
            r#"{"risk_level":"HIGH","overall_mismatch_score":1e400,"functions":[]}"#,
            r#"{"risk_level":"HIGH","overall_mismatch_score":0.5,"functions":[{"name":"withdraw","mismatch_score":1e400}]}"#,
        ] {
            assert_schema_drift(body);
        }
    }

    #[test]
    fn parse_report_rejects_malformed_json_as_decode_error() {
        let error = parse_report("{not-json").expect_err("malformed JSON must fail");
        assert!(error.starts_with("decode:"), "got {error:?}");
    }

    async fn scan_body(body: String) -> DetectorOutcome {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind loopback listener");
        let address = listener.local_addr().expect("read listener address");
        let app = axum::Router::new().route(
            "/scan",
            axum::routing::post(move || {
                let body = body.clone();
                async move { axum::response::Response::new(axum::body::Body::from(body)) }
            }),
        );
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            axum::serve(listener, app)
                .with_graceful_shutdown(async {
                    let _ = shutdown_rx.await;
                })
                .await
                .expect("serve loopback scan endpoint");
        });

        let client = DetectorClient::new(format!("http://{address}"), Duration::from_secs(2));
        let outcome = client.scan_source("contract C {}").await;
        let _ = shutdown_tx.send(());
        server.await.expect("join loopback server");
        outcome
    }

    #[tokio::test]
    async fn scan_source_returns_scanned_for_valid_body_and_unavailable_for_drift() {
        let valid = valid_report_json("CRITICAL");
        assert!(matches!(
            scan_body(valid).await,
            DetectorOutcome::Scanned(DetectorReport { .. })
        ));

        let drifted = valid_report_json("EXTREME");
        match scan_body(drifted).await {
            DetectorOutcome::Unavailable(reason) => {
                assert!(reason.contains("schema drift"), "got {reason:?}");
            }
            outcome => panic!("drifted report must fail open as unavailable, got {outcome:?}"),
        }
    }

    #[tokio::test]
    async fn unreachable_sidecar_fails_open() {
        // Port 1 is unused: the client must NOT error — it returns Unavailable.
        let client = DetectorClient::new("http://127.0.0.1:1", Duration::from_millis(300));
        let outcome = client.scan_source("contract C {}").await;
        assert!(
            matches!(outcome, DetectorOutcome::Unavailable(_)),
            "unreachable sidecar must fail open, got {outcome:?}"
        );
    }
}
