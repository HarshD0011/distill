//! Optional, bounded text for a human's critical-command dialog. Never a verdict.
use super::{App, providers};
use distill_core::JudgeProvider;
use serde_json::{Value, json};
use std::{
    io::Read,
    path::Path,
    time::{Duration, Instant},
};

const PROMPT_VERSION: &str = "critical-description-1";

fn explanation(response: &Value) -> Result<String, String> {
    if response["model"]
        .as_str()
        .is_some_and(|model| model != "gpt-6-luna" && !model.starts_with("gpt-6-luna-"))
    {
        return Err("Unexpected description model".into());
    }
    let text = providers::response_text(JudgeProvider::OpenaiCompatible, response)?;
    let value: Value = serde_json::from_str(&text).map_err(|_| "Invalid description JSON")?;
    if value.as_object().is_none_or(|value| value.len() != 1) {
        return Err("Unexpected description fields".into());
    }
    let text = value["explanation"]
        .as_str()
        .ok_or("Missing command explanation")?;
    if text.trim().is_empty()
        || text.len() > 2400
        || text.chars().count() > 600
        || text.chars().any(|c| {
            (c.is_control() && !matches!(c, '\n' | '\t' | '\r'))
                || matches!(c, '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
        })
    {
        return Err("Command explanation exceeds display limits".into());
    }
    Ok(distill_core::privacy::redact(
        &text.split_whitespace().collect::<Vec<_>>().join(" "),
    ))
}

impl App {
    pub(super) fn describe_critical(&self, params: Value) -> Result<Value, String> {
        if !self.config.judge.enabled || !self.config.judge.critical_descriptions {
            return Err("Critical descriptions are disabled".into());
        }
        if params["model_policy_digest"] != self.config.model_digest() {
            return Err("Model policy changed; restart the optional service".into());
        }
        let command = params["command"]
            .as_str()
            .filter(|v| !v.is_empty() && v.len() <= 8192)
            .ok_or("Invalid critical description command")?;
        let cwd = params["cwd"]
            .as_str()
            .filter(|v| v.len() <= 4096 && Path::new(v).is_absolute())
            .ok_or("Invalid critical description working directory")?;
        let reason = params["reason"]
            .as_str()
            .filter(|v| v.len() <= 4096)
            .ok_or("Invalid critical description reason")?;
        if params["severity"] != "critical" {
            return Err("Descriptions are limited to critical commands".into());
        }
        // Build an allowlist rather than forwarding arbitrary IPC fields or source.
        let mut evidence =
            json!({"command":command,"cwd":cwd,"static_reason":reason,"severity":"critical"});
        distill_core::privacy::redact_value(&mut evidence);
        let key = distill_core::sha256(
            json!([PROMPT_VERSION, self.config.model_digest(), evidence])
                .to_string()
                .as_bytes(),
        );
        if let Some((created, value)) = self
            .cache
            .lock()
            .map_err(|_| "Cache unavailable")?
            .get(&key)
            && created.elapsed() < Duration::from_secs(60)
        {
            let mut value = value.clone();
            value["cached"] = json!(true);
            return Ok(value);
        }
        let _permit = self.requests.acquire()?;
        let response = providers::description_request(
            &self.client,
            &self.config.judge,
            &evidence,
            self.credential.key(),
        )?
        .timeout(Duration::from_millis(
            self.config.judge.background_deadline_ms.min(1800),
        ))
        .send()
        .map_err(providers::transport_error)?;
        if !response.status().is_success() {
            return Err("Command explanation is unavailable".into());
        }
        let mut bytes = Vec::new();
        response
            .take(16385)
            .read_to_end(&mut bytes)
            .map_err(|_| "Command explanation is unavailable")?;
        if bytes.len() > 16384 {
            return Err("Description response exceeds limit".into());
        }
        let response: Value =
            serde_json::from_slice(&bytes).map_err(|_| "Description response is not JSON")?;
        let text = explanation(&response)?;
        let result = json!({"status":"description","explanation":text,"model":"gpt-6-luna","prompt_version":PROMPT_VERSION,"cached":false});
        let mut cache = self.cache.lock().map_err(|_| "Cache unavailable")?;
        if cache.len() >= 256 {
            cache.clear();
        }
        cache.insert(key, (Instant::now(), result.clone()));
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn response(text: Value) -> Value {
        json!({"choices":[{"finish_reason":"stop","message":{"content":text.to_string()}}]})
    }
    #[test]
    fn explanations_are_bounded_plain_text_and_never_accept_verdict_fields() {
        assert_eq!(
            explanation(&response(
                json!({"explanation":"Deletes files.\nThis cannot be undone."})
            ))
            .unwrap(),
            "Deletes files. This cannot be undone."
        );
        for invalid in [
            json!({"explanation":""}),
            json!({"explanation":"x".repeat(601)}),
            json!({"explanation":"hidden\u{202e}text"}),
            json!({"explanation":"Fine", "decision":"allow"}),
        ] {
            assert!(explanation(&response(invalid)).is_err());
        }
        let mut refused = response(json!({"explanation":"Fine"}));
        refused["choices"][0]["message"]["refusal"] = json!("refused");
        assert!(explanation(&refused).is_err());
    }
}
