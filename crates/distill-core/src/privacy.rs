//! Best-effort presentation redaction, never used as analyzer input.
use regex::Regex;
use std::sync::OnceLock;

pub fn redact_value(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::String(text) => *text = redact(text),
        serde_json::Value::Array(items) => items.iter_mut().for_each(redact_value),
        serde_json::Value::Object(items) => {
            for (key, value) in items {
                if ["password", "token", "secret", "api_key", "authorization"]
                    .iter()
                    .any(|part| key.to_ascii_lowercase().contains(part))
                {
                    *value = serde_json::json!("[REDACTED]");
                } else {
                    redact_value(value);
                }
            }
        }
        _ => {}
    }
}

pub fn redact(text: &str) -> String {
    static RULES: OnceLock<Vec<Regex>> = OnceLock::new();
    let rules = RULES.get_or_init(|| [
        r"(?i)(https?://)[^\s/@:]+:[^\s/@]+@",
        r#"(?i)((?:authorization|proxy-authorization)\s*:\s*(?:bearer|basic)?\s*)[^\s'\";]+"#,
        r#"(?i)((?:[a-z_]*?(?:token|password|passwd|secret|api_key|apikey|access_key|private_key)[a-z_]*|AWS_ACCESS_KEY_ID)\s*[=:]\s*)(?:"[^"\n]*"|'[^'\n]*'|[^\s;]+)"#,
        r#"(?i)((?:--password|--token|--secret|--api-key|--access-key|-u|--user)\s+)(?:"[^"\n]*"|'[^'\n]*'|[^\s;]+)"#,
        r"\b(?:sk-[A-Za-z0-9_-]{16,}|gh[pousr]_[A-Za-z0-9_]{20,}|AKIA[A-Z0-9]{16})\b",
        r"(?s)-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----",
    ].into_iter().map(|pattern| Regex::new(pattern).expect("built-in redaction regex")).collect());
    rules.iter().fold(text.to_owned(), |value, rule| {
        rule.replace_all(&value, |caps: &regex::Captures<'_>| {
            format!(
                "{}[REDACTED]{}",
                caps.get(1).map_or("", |m| m.as_str()),
                if caps.get(1).is_some_and(|m| m.as_str().ends_with("://")) {
                    "@"
                } else {
                    ""
                }
            )
        })
        .into_owned()
    })
}

#[cfg(test)]
mod tests {
    #[test]
    fn presentation_removes_common_credentials() {
        let text = super::redact(
            "TOKEN=top-secret curl -H 'Authorization: Bearer abcdef' https://user:pass@example.com --password xyz",
        );
        for secret in ["top-secret", "abcdef", "user:pass", "xyz"] {
            assert!(!text.contains(secret), "{text}");
        }
        assert!(text.contains("example.com"));
        let text = super::redact("PASSWORD='two secret words' --token \"another secret phrase\"");
        assert!(
            !text.contains("words") && !text.contains("phrase"),
            "{text}"
        );
    }
}
