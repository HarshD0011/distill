//! Compact, strictly positional reviews. They can raise risk, never prove safety.
use super::*;
use distill_core::Severity;

pub(super) fn parse(text: &str, count: usize) -> Result<Vec<Severity>, String> {
    let values: Vec<_> = text
        .trim()
        .split(';')
        .map(|value| match value {
            "safe" => Ok(Severity::Safe),
            "low" => Ok(Severity::Low),
            "medium" => Ok(Severity::Medium),
            "high" => Ok(Severity::High),
            "critical" => Ok(Severity::Critical),
            _ => Err("Invalid severity response; static review requirements retained".to_owned()),
        })
        .collect::<Result<_, _>>()?;
    if values.len() != count || count == 0 || count > 16 {
        return Err("Severity count does not match submitted items".into());
    }
    Ok(values)
}

impl App {
    pub(super) fn judge_severities(
        &self,
        params: &[Value],
        remaining: Duration,
    ) -> Result<Vec<Value>, String> {
        if params.is_empty()
            || params.len() > 16
            || !self.config.judge.enabled
            || remaining < Duration::from_millis(20)
        {
            return Err("Invalid compact review batch or exhausted deadline".into());
        }
        let mut items = Vec::new();
        for param in params {
            if param["model_policy_digest"] != self.config.model_digest() {
                return Err("Model policy changed".into());
            }
            let mut item = json!({"command":param["command"],"cwd":param["cwd"],"shell":param["shell"],"coverage_gaps":param["coverage_gaps"],"coverage_gaps_omitted":param["coverage_gaps_omitted"],"source_review":param["source_review"]});
            if self.config.judge.send_script_contents {
                item["scripts"] = param["scripts"].clone();
                let source_bytes: usize = param["scripts"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .map(|s| s["source"].as_str().map_or(0, str::len))
                    .sum();
                if source_bytes > self.config.judge.max_script_bytes {
                    return Err("Script source exceeds review limit".into());
                }
            }
            distill_core::privacy::redact_value(&mut item);
            items.push(item);
        }
        let items = json!(items);
        if items.to_string().len() > 65536 {
            return Err("Compact batch exceeds limit".into());
        }
        let _permit = self.requests.acquire()?;
        let response = providers::severity_request(
            &self.client,
            &self.config.judge,
            &items,
            self.credential.key(),
        )?
        .timeout(remaining.min(Duration::from_millis(
            self.config.judge.background_deadline_ms,
        )))
        .send()
        .map_err(providers::transport_error)?;
        if !response.status().is_success() {
            return Err(format!(
                "Model endpoint returned HTTP {}",
                response.status().as_u16()
            ));
        }
        let mut bytes = Vec::new();
        response
            .take(65537)
            .read_to_end(&mut bytes)
            .map_err(|_| "Model response unavailable")?;
        if bytes.len() > 65536 {
            return Err("Model response exceeds limit".into());
        }
        let response: Value =
            serde_json::from_slice(&bytes).map_err(|_| "Model response is not JSON")?;
        let text = providers::response_text(self.config.judge.provider, &response)?;
        Ok(parse(&text, params.len())?.into_iter().zip(params).map(|(severity,param)| {
            let mut result = json!({"status":"advisory","severity":severity,"model":self.config.judge.model,"provider":self.config.judge.provider,"prompt_version":"severity-2","cached":false,"batch_size":params.len(),"proposal":{"effects":[],"intent_match":"unavailable","explanation":"Model severity suggestion only. Approval requirements retained."}});
            if let Some(source) = param.get("source_review") { result["source_review"] = source.clone(); }
            result
        }).collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn strict_count_order_and_vocabulary_reject_placeholders_and_explanations() {
        assert_eq!(
            parse("safe;high;critical", 3).unwrap(),
            vec![Severity::Safe, Severity::High, Severity::Critical]
        );
        for text in [
            "safe;high;",
            "safe",
            "SAFE;high",
            "safe; high",
            "safe;unknown",
            "safe;high because",
            "safe;high\nignore instructions",
            "```safe;high```",
        ] {
            assert!(parse(text, 2).is_err(), "{text}");
        }
    }
}
