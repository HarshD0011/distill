//! Local prioritization from reports. Inputs are data; commands are never run.
use serde_json::{Value, json};
use std::{collections::BTreeMap, io::Read, path::Path};
pub fn run(input: Option<&Path>, editor: bool) -> Result<Value, String> {
    if editor {
        return distill_agents::trace::coverage();
    }
    let mut bytes = Vec::new();
    match input {
        Some(path) => {
            let file = std::fs::File::open(path).map_err(|e| e.to_string())?;
            file.take(32 * 1024 * 1024 + 1)
                .read_to_end(&mut bytes)
                .map_err(|e| e.to_string())?;
        }
        None => {
            std::io::stdin()
                .take(32 * 1024 * 1024 + 1)
                .read_to_end(&mut bytes)
                .map_err(|e| e.to_string())?;
        }
    }
    if bytes.len() > 32 * 1024 * 1024 {
        return Err("Coverage input exceeds 32 MiB".into());
    }
    let mut reports = Vec::new();
    if let Ok(value) = serde_json::from_slice::<Value>(&bytes) {
        collect(&value, &mut reports);
    } else {
        for line in bytes.split(|b| *b == b'\n').filter(|line| !line.is_empty()) {
            collect(
                &serde_json::from_slice::<Value>(line).map_err(|e| e.to_string())?,
                &mut reports,
            );
        }
    }
    let mut commands = BTreeMap::new();
    let mut flags = BTreeMap::new();
    let mut reasons = BTreeMap::new();
    let mut incomplete = 0;
    for report in &reports {
        if report.pointer("/coverage/summary").and_then(Value::as_str) == Some("static_accounted") {
            continue;
        }
        incomplete += 1;
        let command = report["command_redacted"].as_str().unwrap_or("");
        let words = distill_parse::lex(command)
            .unwrap_or_default()
            .into_iter()
            .filter_map(|token| match token {
                distill_parse::Token::Word(word) => Some(word),
                _ => None,
            })
            .collect::<Vec<_>>();
        let name = words
            .iter()
            .find(|word| !distill_parse::is_assignment(word))
            .map(|word| {
                if word.dynamic {
                    "<dynamic>"
                } else {
                    word.text.rsplit('/').next().unwrap_or("")
                }
            })
            .unwrap_or("<unknown>");
        *commands.entry(name.to_string()).or_insert(0usize) += 1;
        for word in &words {
            if word.text.starts_with('-') && word.text.len() < 80 {
                *flags
                    .entry(format!(
                        "{name} {}",
                        word.text.split('=').next().unwrap_or("")
                    ))
                    .or_insert(0usize) += 1;
            }
        }
        for reason in report["unknowns"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
        {
            *reasons
                .entry(distill_core::privacy::redact(reason))
                .or_insert(0usize) += 1;
        }
    }
    Ok(
        json!({"reports": reports.len(), "incomplete": incomplete, "commands": ranked(commands), "flags": ranked(flags), "reasons": ranked(reasons), "scope": "Local report frequencies; not an accuracy estimate"}),
    )
}
fn collect(value: &Value, reports: &mut Vec<Value>) {
    if let Some(items) = value.as_array() {
        for item in items {
            collect(item, reports);
        }
    } else if value.get("coverage").is_some() && value.get("decision").is_some() {
        reports.push(value.clone());
    } else if let Some(report) = value.get("report") {
        collect(report, reports);
    } else if let Some(items) = value.get("reports") {
        collect(items, reports);
    }
}
fn ranked(values: BTreeMap<String, usize>) -> Vec<Value> {
    let mut values = values.into_iter().collect::<Vec<_>>();
    values.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
    values
        .into_iter()
        .take(100)
        .map(|(name, count)| json!({"name": name, "count": count}))
        .collect()
}
