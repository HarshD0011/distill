//! Bounded, memory-only model work. Enqueue never waits for a provider response.
use super::*;

const MAX_JOBS: usize = 256;
const MAX_RUNNING: usize = crate::concurrency::MAX_MODEL_REQUESTS;
const SUCCESS_TTL: Duration = Duration::from_secs(60);
const FAILURE_TTL: Duration = Duration::from_secs(5);

struct Job {
    updated: Instant,
    value: Value,
}
#[derive(Default)]
pub(super) struct Jobs {
    entries: BTreeMap<String, Job>,
    running: usize,
    cooldown: Option<Instant>,
    last_failure: Option<String>,
    waiting: Vec<(String, Value, Instant)>,
    batch_scheduled: bool,
}

impl App {
    pub(super) fn enqueue(self: &Arc<Self>, mut params: Value) -> Result<Value, String> {
        if !self.config.judge.enabled || params["model_policy_digest"] != self.config.model_digest()
        {
            return Err(
                "Model routing is disabled or its policy changed; restart the service".into(),
            );
        }
        let object = params
            .as_object_mut()
            .ok_or("Judge parameters must be an object")?;
        object.remove("remaining_ms");
        if !self.config.judge.send_script_contents {
            object.remove("scripts");
        }
        if params.to_string().len() > 65536 {
            return Err("Judge payload exceeds limit".into());
        }
        if params["command"].as_str().is_none_or(|v| v.is_empty()) {
            return Err("Judge command is missing".into());
        }
        if !Path::new(text(&params, "cwd")?).is_absolute() {
            return Err("Judge cwd must be absolute".into());
        }
        distill_core::privacy::redact_value(&mut params);
        let key = distill_core::sha256(
            json!([params, self.config.digest(), "background-1"])
                .to_string()
                .as_bytes(),
        );
        let mut jobs = self.jobs.lock().map_err(|_| "Model queue unavailable")?;
        jobs.entries.retain(|_, job| {
            job.value["status"] == "pending"
                || job.updated.elapsed()
                    < if job.value["status"] == "advisory" {
                        SUCCESS_TTL
                    } else {
                        FAILURE_TTL
                    }
        });
        if let Some(job) = jobs.entries.get(&key) {
            let mut value = job.value.clone();
            value["cached"] = json!(value["status"] == "advisory");
            return Ok(value);
        }
        if jobs.cooldown.is_some_and(|until| until > Instant::now()) {
            return Ok(
                json!({"status":"unavailable","reason":"Recent model request failed; retry after the brief cooldown.","detail":jobs.last_failure,"retry_after_ms":5000}),
            );
        }
        if (jobs.running >= MAX_RUNNING && !jobs.batch_scheduled)
            || jobs.entries.len() >= MAX_JOBS
            || jobs.waiting.len() >= 16
            || (!jobs.waiting.is_empty()
                && jobs
                    .waiting
                    .iter()
                    .map(|(_, v, _)| v.to_string().len())
                    .sum::<usize>()
                    + params.to_string().len()
                    > 65536)
        {
            return Ok(
                json!({"status":"busy","reason":"Background model queue is full; static review requirements retained."}),
            );
        }
        let pending = json!({"status":"pending","request_digest":key,"model":self.config.judge.model,"provider":self.config.judge.provider,"cached":false,"reason":"Background model review queued. Static review requirements apply while advice is pending."});
        jobs.entries.insert(
            key.clone(),
            Job {
                updated: Instant::now(),
                value: pending.clone(),
            },
        );
        if self.config.judge.review_format == distill_core::ReviewFormat::Severity
            && self.config.judge.batch_window_ms > 0
        {
            jobs.waiting.push((key.clone(), params, Instant::now()));
            if jobs.batch_scheduled {
                return Ok(pending);
            }
            jobs.batch_scheduled = true;
            jobs.running += 1;
            drop(jobs);
            let app = Arc::clone(self);
            if std::thread::Builder::new().name("distill-severity-batch".into()).spawn(move || {
                // Fixed from the first arrival; a stream of new commands cannot
                // keep extending the window and starve the oldest command.
                std::thread::sleep(Duration::from_millis(app.config.judge.batch_window_ms));
                let batch = {
                    let Ok(mut jobs) = app.jobs.lock() else { return; };
                    jobs.batch_scheduled = false;
                    std::mem::take(&mut jobs.waiting)
                };
                let queued_ms = batch.iter().map(|(_,_,time)| time.elapsed().as_millis() as u64).max().unwrap_or(0);
                let remaining = app.config.judge.background_deadline_ms.saturating_sub(queued_ms);
                let params: Vec<_> = batch.iter().map(|(_,value,_)| value.clone()).collect();
                let result = app.judge_severities(&params, Duration::from_millis(remaining));
                if let Ok(mut jobs) = app.jobs.lock() {
                    jobs.running = jobs.running.saturating_sub(1);
                    let values = match result {
                        Ok(values) => values,
                        Err(error) => {
                            jobs.cooldown = Some(Instant::now() + FAILURE_TTL);
                            jobs.last_failure = Some(error.clone());
                            vec![json!({"status":"unavailable","reason":error,"retry_after_ms":5000}); batch.len()]
                        }
                    };
                    for ((key,_,created), mut value) in batch.into_iter().zip(values) {
                        value["request_digest"] = json!(key);
                        value["elapsed_ms"] = json!(created.elapsed().as_millis());
                        value["queue_ms"] = json!(queued_ms);
                        jobs.entries.insert(key, Job { updated: Instant::now(), value });
                    }
                }
            }).is_err() {
                if let Ok(mut jobs) = self.jobs.lock() {
                    let keys: Vec<_> = jobs.waiting.drain(..).map(|(key,_,_)| key).collect();
                    for key in keys { jobs.entries.remove(&key); }
                    jobs.batch_scheduled = false;
                    jobs.running = jobs.running.saturating_sub(1);
                }
                return Err("Could not start bounded severity worker".into());
            }
            return Ok(pending);
        }
        jobs.running += 1;
        drop(jobs);
        let app = Arc::clone(self);
        let thread_key = key.clone();
        let worker = std::thread::Builder::new()
            .name("distill-model".into())
            .spawn(move || {
                params["remaining_ms"] = json!(app.config.judge.background_deadline_ms);
                let started = Instant::now();
                let result =
                    if app.config.judge.review_format == distill_core::ReviewFormat::Severity {
                        app.judge_severities(
                            &[params.clone()],
                            Duration::from_millis(app.config.judge.background_deadline_ms),
                        )
                        .and_then(|values| {
                            values
                                .into_iter()
                                .next()
                                .ok_or_else(|| "Missing severity result".into())
                        })
                    } else {
                        app.judge_with_deadline(params.clone(), true)
                    };
                let mut value = match result {
                    Ok(mut value) => {
                        if value.get("severity").is_none() {
                            value["severity"] = json!(app.advice_severity(&params, &value));
                        }
                        value
                    }
                    Err(error) => {
                        json!({"status":"unavailable","reason":error,"retry_after_ms":5000})
                    }
                };
                value["request_digest"] = json!(thread_key);
                value["elapsed_ms"] = json!(started.elapsed().as_millis());
                if let Ok(mut jobs) = app.jobs.lock() {
                    jobs.running = jobs.running.saturating_sub(1);
                    if value["status"] != "advisory" {
                        jobs.cooldown = Some(Instant::now() + FAILURE_TTL);
                        jobs.last_failure = value["reason"].as_str().map(str::to_owned);
                    }
                    jobs.entries.insert(
                        thread_key,
                        Job {
                            updated: Instant::now(),
                            value,
                        },
                    );
                }
            });
        if worker.is_err() {
            if let Ok(mut jobs) = self.jobs.lock() {
                jobs.entries.remove(&key);
                jobs.running = jobs.running.saturating_sub(1);
            }
            return Err("Could not start bounded model worker".into());
        }
        Ok(pending)
    }

    fn advice_severity(&self, params: &Value, value: &Value) -> distill_core::Severity {
        use distill_core::{
            AnalyzeRequest, CommandForm, CommandKind, Integration, Severity, ShellDialect,
        };
        let request = AnalyzeRequest {
            protocol_version: distill_core::PROTOCOL_VERSION,
            request_id: "model-proposal".into(),
            command: CommandForm {
                kind: CommandKind::Shell,
                text: params["command"].as_str().unwrap_or("").into(),
                dialect: serde_json::from_value(params["shell"].clone())
                    .unwrap_or(ShellDialect::Bash),
            },
            cwd: PathBuf::from(params["cwd"].as_str().unwrap_or("/")),
            session_id: None,
            source: Integration::Cli,
            budget_ms: 30,
            context: serde_json::from_value(params["shell_context"].clone()).unwrap_or_default(),
        };
        let effects = value
            .pointer("/proposal/effects")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        let proposed = distill_interp::proposed_effects(&request, &effects, &self.config);
        let classifier: Severity = serde_json::from_value(value["classifier"]["severity"].clone())
            .unwrap_or(Severity::Safe);
        proposed
            .max_severity
            .unwrap_or(Severity::Safe)
            .max(classifier)
    }

    pub(super) fn advice_results(&self, params: Value) -> Result<Value, String> {
        if !self.config.judge.enabled || params["model_policy_digest"] != self.config.model_digest()
        {
            return Err("Model routing is disabled or its policy changed".into());
        }
        let keys = params["request_digests"]
            .as_array()
            .filter(|v| v.len() <= 16)
            .ok_or("At most 16 model request digests are allowed")?;
        if keys.iter().any(|key| {
            key.as_str()
                .is_none_or(|s| s.len() != 64 || !s.bytes().all(|c| c.is_ascii_hexdigit()))
        }) {
            return Err("Invalid model request digest".into());
        }
        let jobs = self.jobs.lock().map_err(|_| "Model queue unavailable")?;
        let values: Vec<_> = keys.iter().map(|key| {
            jobs.entries.get(key.as_str().unwrap()).filter(|job| job.value["status"] == "pending" || job.updated.elapsed() < SUCCESS_TTL).map(|job| job.value.clone()).unwrap_or_else(|| json!({"status":"expired","request_digest":key,"reason":"Background result expired or service restarted; retry the command for a fresh assessment."}))
        }).collect();
        Ok(json!({"results":values}))
    }
}
