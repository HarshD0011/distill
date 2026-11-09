//! One-shot inherited-pipe handoff. Never serialize credentials into IPC or logs.
use crate::{JudgeConfig, JudgeProvider};
use serde::{Deserialize, Serialize};
use std::io::{Read, Write};
use zeroize::{Zeroize, Zeroizing};

// Intentionally no Debug implementation: errors must never contain the key.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceCredential {
    provider: JudgeProvider,
    endpoint: String,
    api_key_env: String,
    key: Option<String>,
}
impl Drop for ServiceCredential {
    fn drop(&mut self) {
        if let Some(key) = &mut self.key {
            key.zeroize();
        }
    }
}
impl ServiceCredential {
    pub fn read(reader: impl Read, config: &JudgeConfig) -> Result<Self, String> {
        let mut bytes = Zeroizing::new(Vec::new());
        reader
            .take(20481)
            .read_to_end(&mut bytes)
            .map_err(|_| "Credential handoff unavailable")?;
        if bytes.len() > 20480 {
            return Err("Credential handoff exceeds limit".into());
        }
        let value: Self =
            serde_json::from_slice(&bytes).map_err(|_| "Invalid credential handoff")?;
        value.validate(config)?;
        Ok(value)
    }
    pub fn from_environment(config: &JudgeConfig) -> Result<Self, String> {
        let value = Self {
            provider: config.provider,
            endpoint: config.endpoint.clone(),
            api_key_env: config.api_key_env.clone(),
            key: if config.api_key_env.is_empty() {
                None
            } else {
                std::env::var(&config.api_key_env).ok()
            },
        };
        value.validate(config)?;
        Ok(value)
    }
    fn validate(&self, config: &JudgeConfig) -> Result<(), String> {
        if self.provider != config.provider
            || self.endpoint != config.endpoint
            || self.api_key_env != config.api_key_env
        {
            return Err("Credential route does not match service policy".into());
        }
        if self.key.as_ref().is_some_and(|key| {
            self.api_key_env.is_empty()
                || key.trim().is_empty()
                || key.len() > 16384
                || key.contains(['\r', '\n', '\0'])
        }) {
            return Err("Invalid provider credential".into());
        }
        Ok(())
    }
    pub fn key(&self) -> Option<&str> {
        self.key.as_deref()
    }
    pub fn write(&self, mut writer: impl Write) -> Result<(), String> {
        let bytes =
            Zeroizing::new(serde_json::to_vec(self).map_err(|_| "Credential encoding failed")?);
        writer
            .write_all(&bytes)
            .map_err(|_| "Credential handoff failed".into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn pipe_credentials_are_bounded_route_bound_and_errors_never_echo_input() {
        let config = JudgeConfig::default();
        let make = |endpoint: &str, key: &str| {
            serde_json::json!({"provider":"openai_compatible","endpoint":endpoint,"api_key_env":"OPENAI_API_KEY","key":key}).to_string()
        };
        let valid = make(&config.endpoint, "fixture-secret");
        let credential = ServiceCredential::read(valid.as_bytes(), &config).unwrap();
        assert_eq!(credential.key(), Some("fixture-secret"));
        for invalid in [
            make("https://other.invalid", "fixture-secret"),
            make(&config.endpoint, "fixture-secret\n"),
            "fixture-secret".repeat(3000),
        ] {
            let error = ServiceCredential::read(invalid.as_bytes(), &config)
                .err()
                .unwrap();
            assert!(!error.contains("fixture-secret"));
        }
    }
}
