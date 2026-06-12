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
    #[serde(default)]
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
    #[serde(default)]
    pub functions: Vec<FunctionFinding>,
}

impl DetectorReport {
    /// Map the detector's textual risk level onto the shared [`RiskLevel`] grade.
    pub fn risk(&self) -> RiskLevel {
        match self.risk_level.to_ascii_uppercase().as_str() {
            "CRITICAL" => RiskLevel::Critical,
            "HIGH" => RiskLevel::High,
            "MEDIUM" => RiskLevel::Medium,
            _ => RiskLevel::Low,
        }
    }
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
            Ok(resp) => match resp.json::<DetectorReport>().await {
                Ok(report) => DetectorOutcome::Scanned(report),
                Err(e) => DetectorOutcome::Unavailable(format!("decode: {e}")),
            },
            Err(e) => DetectorOutcome::Unavailable(format!("transport: {e}")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn report_maps_textual_risk_levels() {
        let mut r = DetectorReport {
            risk_level: "critical".into(),
            overall_mismatch_score: 0.9,
            recommended_action: String::new(),
            functions: vec![],
        };
        assert_eq!(r.risk(), RiskLevel::Critical);
        r.risk_level = "HIGH".into();
        assert_eq!(r.risk(), RiskLevel::High);
        r.risk_level = "anything-else".into();
        assert_eq!(r.risk(), RiskLevel::Low);
    }

    #[test]
    fn deserializes_report_ignoring_unknown_fields() {
        let json = r#"{
            "contract_address": "0xabc",
            "risk_level": "MEDIUM",
            "overall_mismatch_score": 0.31,
            "recommended_action": "review",
            "functions": [{ "name": "withdraw", "mismatch_score": 0.42, "extra": 1 }]
        }"#;
        let report: DetectorReport = serde_json::from_str(json).expect("decodes");
        assert_eq!(report.risk(), RiskLevel::Medium);
        assert_eq!(report.functions.len(), 1);
        assert_eq!(report.functions[0].name, "withdraw");
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
