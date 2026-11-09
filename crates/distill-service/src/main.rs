//! Optional service. Neither SQLite nor HTTP is linked into the hook binary.
use clap::Parser;
use distill_core::{Config, service_ipc};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    fs,
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
mod background;
mod concurrency;
mod providers;
mod severity;

#[derive(Parser)]
#[command(version=distill_core::PRODUCT_VERSION)]
struct Args {
    #[arg(long)]
    config: Option<PathBuf>,
    /// Exit and discard in-memory credentials/cache when this editor host exits.
    #[arg(long)]
    owner_pid: Option<i32>,
    #[arg(long)]
    credential_stdin: bool,
}
struct App {
    config: Config,
    db: Mutex<Option<rusqlite::Connection>>,
    client: reqwest::blocking::Client,
    cache: Mutex<BTreeMap<String, (Instant, Value)>>,
    stop: AtomicBool,
    classifier: Option<(Value, String)>,
    jobs: Mutex<background::Jobs>,
    credential: distill_core::credentials::ServiceCredential,
    requests: concurrency::Requests,
}

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}
fn text<'a>(v: &'a Value, key: &str) -> Result<&'a str, String> {
    v[key]
        .as_str()
        .filter(|v| !v.is_empty() && v.len() <= 4096)
        .ok_or_else(|| format!("Missing or oversized {key}"))
}
fn session_key(event: &Value) -> Result<String, String> {
    let source = text(event, "source")?;
    if !["codex", "claude", "cli"].contains(&source) {
        return Err("Unsupported event source".into());
    }
    let cwd = text(event, "session_cwd")?;
    if !Path::new(cwd).is_absolute() {
        return Err("Event cwd must be absolute".into());
    }
    Ok(distill_core::sha256(
        json!([source, text(event, "session_id")?, cwd])
            .to_string()
            .as_bytes(),
    ))
}

fn database(config: &Config, dir: &Path) -> Result<Option<rusqlite::Connection>, String> {
    if !config.service.history_enabled {
        return Ok(None);
    }
    let path = dir.join("events.db");
    let mut options = fs::OpenOptions::new();
    options.write(true).create(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    options.open(&path).map_err(|e| e.to_string())?;
    // Validate type and ownership without following links before opening SQLite.
    let meta = fs::symlink_metadata(&path).map_err(|e| e.to_string())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if !meta.is_file()
            || meta.file_type().is_symlink()
            || meta.uid() != unsafe { libc::geteuid() }
            || meta.mode() & 0o077 != 0
        {
            return Err("History database is not private".into());
        }
    }
    let db = rusqlite::Connection::open(&path).map_err(|e| e.to_string())?;
    db.busy_timeout(Duration::from_millis(15))
        .map_err(|e| e.to_string())?;
    db.execute_batch(&format!("PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON; PRAGMA max_page_count={}; PRAGMA journal_size_limit=1048576; CREATE TABLE IF NOT EXISTS meta(version INTEGER NOT NULL); INSERT INTO meta SELECT 1 WHERE NOT EXISTS(SELECT 1 FROM meta); CREATE TABLE IF NOT EXISTS events(event_id TEXT PRIMARY KEY, session_key TEXT NOT NULL, tool_id TEXT NOT NULL, kind TEXT NOT NULL, timestamp INTEGER NOT NULL, cwd TEXT NOT NULL, payload TEXT NOT NULL); CREATE INDEX IF NOT EXISTS events_session ON events(session_key,timestamp); CREATE TABLE IF NOT EXISTS feedback(id INTEGER PRIMARY KEY,session_key TEXT NOT NULL,tool_id TEXT NOT NULL,kind TEXT NOT NULL,severity TEXT,note TEXT NOT NULL,timestamp INTEGER NOT NULL);",config.service.max_bytes/4096)).map_err(|e|e.to_string())?;
    let version: i64 = db
        .query_row("SELECT version FROM meta", [], |r| r.get(0))
        .map_err(|e| e.to_string())?;
    if version != 1 {
        return Err("Unsupported history schema".into());
    }
    Ok(Some(db))
}

impl App {
    fn record(&self, mut event: Value) -> Result<Value, String> {
        if !self.config.service.history_enabled {
            return Err("Persistent history is disabled".into());
        }
        let key = session_key(&event)?;
        let event_id = text(&event, "event_id")?.to_owned();
        let tool_id = text(&event, "tool_use_id")?.to_owned();
        let kind = text(&event, "kind")?.to_owned();
        if !["assessment", "completion", "failure"].contains(&kind.as_str()) {
            return Err("Unsupported event kind".into());
        }
        if !self.config.capture_editor_output() {
            event["tool_response"] = Value::Null;
            event["error"] = Value::Null;
            event["output_capture_disabled"] = json!(true);
        }
        distill_core::privacy::redact_value(&mut event);
        let payload = event.to_string();
        if payload.len() > service_ipc::MAX_MESSAGE {
            return Err("Event exceeds history limit".into());
        }
        let timestamp = event["timestamp"]
            .as_i64()
            .filter(|v| *v >= 0 && *v <= now() + 60000)
            .ok_or("Invalid event timestamp")?;
        let cwd = text(&event, "session_cwd")?;
        let mut locked = self.db.lock().map_err(|_| "History unavailable")?;
        let db = locked.as_mut().ok_or("Persistent history is disabled")?;
        let tx = db.transaction().map_err(|e| e.to_string())?;
        tx.execute(
            "INSERT OR IGNORE INTO events VALUES(?1,?2,?3,?4,?5,?6,?7)",
            rusqlite::params![event_id, key, tool_id, kind, timestamp, cwd, payload],
        )
        .map_err(|e| e.to_string())?;
        let cutoff = now().saturating_sub(i64::from(self.config.history.retention_days) * 86400000);
        tx.execute("DELETE FROM events WHERE timestamp<?1", [cutoff])
            .map_err(|e| e.to_string())?;
        tx.execute("DELETE FROM events WHERE event_id IN(SELECT event_id FROM events ORDER BY timestamp DESC LIMIT -1 OFFSET ?1)",[self.config.service.max_events as i64]).map_err(|e|e.to_string())?;
        tx.execute("DELETE FROM feedback WHERE timestamp<?1", [cutoff])
            .map_err(|e| e.to_string())?;
        tx.execute("DELETE FROM feedback WHERE id IN(SELECT id FROM feedback ORDER BY id DESC LIMIT -1 OFFSET ?1)",[self.config.service.max_events as i64]).map_err(|e|e.to_string())?;
        let mut bytes: i64 = tx
            .query_row(
                "SELECT COALESCE(SUM(length(payload)),0) FROM events",
                [],
                |r| r.get(0),
            )
            .map_err(|e| e.to_string())?;
        while bytes as u64 > self.config.service.max_bytes.saturating_sub(1024 * 1024) {
            let (id, len): (String, i64) = tx
                .query_row(
                    "SELECT event_id,length(payload) FROM events ORDER BY timestamp LIMIT 1",
                    [],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .map_err(|e| e.to_string())?;
            tx.execute("DELETE FROM events WHERE event_id=?1", [id])
                .map_err(|e| e.to_string())?;
            bytes -= len;
        }
        tx.commit().map_err(|e| e.to_string())?;
        Ok(json!({"event_id":event_id,"session_key":key}))
    }

    fn query(&self, params: &Value) -> Result<Value, String> {
        let root = params.get("root").and_then(Value::as_str).map(Path::new);
        if root.is_some_and(|v| !v.is_absolute()) {
            return Err("Query root must be absolute".into());
        }
        let session = params.get("session_key").and_then(Value::as_str);
        let limit = params["limit"]
            .as_u64()
            .unwrap_or(1000)
            .min(self.config.service.max_events as u64) as usize;
        let offset = params["offset"].as_u64().unwrap_or(0).min(100000) as usize;
        let locked = self.db.lock().map_err(|_| "History unavailable")?;
        let db = locked.as_ref().ok_or("Persistent history is disabled")?;
        let mut statement=db.prepare("SELECT session_key,cwd,payload FROM events WHERE timestamp>=?1 ORDER BY timestamp DESC LIMIT ?2").map_err(|e|e.to_string())?;
        let cutoff = now().saturating_sub(i64::from(self.config.history.retention_days) * 86400000);
        let rows = statement
            .query_map(
                rusqlite::params![cutoff, self.config.service.max_events as i64],
                |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, String>(1)?,
                        r.get::<_, String>(2)?,
                    ))
                },
            )
            .map_err(|e| e.to_string())?;
        let mut events = Vec::new();
        let mut session_keys = std::collections::BTreeSet::new();
        let mut has_more = false;
        let mut seen = 0;
        let mut bytes = 0;
        for row in rows {
            let (key, cwd, payload) = row.map_err(|e| e.to_string())?;
            if session.is_some_and(|v| v != key)
                || root.is_some_and(|v| !Path::new(&cwd).starts_with(v))
            {
                continue;
            }
            if seen < offset {
                seen += 1;
                continue;
            }
            if events.len() >= limit
                || bytes + payload.len() > service_ipc::MAX_MESSAGE - 256 * 1024
            {
                has_more = true;
                break;
            }
            bytes += payload.len();
            session_keys.insert(key);
            events.push(serde_json::from_str::<Value>(&payload).map_err(|e| e.to_string())?);
        }
        events.reverse();
        let mut feedback = Vec::new();
        let mut statement=db.prepare("SELECT session_key,tool_id,kind,severity,note,timestamp FROM feedback WHERE timestamp>=?1 ORDER BY id DESC LIMIT ?2").map_err(|e|e.to_string())?;
        let rows = statement
            .query_map(
                rusqlite::params![cutoff, self.config.service.max_events as i64],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, Option<String>>(3)?,
                        row.get::<_, String>(4)?,
                        row.get::<_, i64>(5)?,
                    ))
                },
            )
            .map_err(|e| e.to_string())?;
        for row in rows {
            let (key, tool, kind, severity, note, timestamp) = row.map_err(|e| e.to_string())?;
            if !session_keys.contains(&key) {
                continue;
            }
            let value = json!({"session_key":key,"tool_id":tool,"kind":kind,"severity":severity,"note":note,"timestamp":timestamp});
            let size = value.to_string().len();
            if bytes + size > service_ipc::MAX_MESSAGE - 8192 {
                break;
            }
            bytes += size;
            feedback.push(value);
        }
        feedback.reverse();
        Ok(
            json!({"events":events,"feedback":feedback,"has_more":has_more,"next_offset":offset+events.len(),"retention_days":self.config.history.retention_days}),
        )
    }

    fn handle(self: &Arc<Self>, method: &str, params: Value) -> Result<Value, String> {
        match method {
            "hello" => Ok(
                json!({"v":1,"version":distill_core::PRODUCT_VERSION,"policy_digest":self.config.digest(),"history_enabled":self.config.service.history_enabled,"judge_enabled":self.config.judge.enabled,"classifier_enabled":self.classifier.is_some(),"max_model_requests":concurrency::MAX_MODEL_REQUESTS,"model_requests_in_flight":self.requests.in_flight(),"capabilities":["query","feedback","export","stats","judge","judge_enqueue","judge_results","purge","idempotent-events","model-agnostic-router"]}),
            ),
            "record" => self.record(params["event"].clone()),
            "query" | "export" => self.query(&params),
            "feedback" => {
                let kind = text(&params, "kind")?;
                if !["over", "under"].contains(&kind) {
                    return Err("Feedback must be over or under".into());
                }
                let note = params["note"].as_str().unwrap_or("");
                if note.len() > 2048 {
                    return Err("Feedback note exceeds limit".into());
                }
                let locked = self.db.lock().map_err(|_| "History unavailable")?;
                let db = locked.as_ref().ok_or("Persistent history is disabled")?;
                let count: i64 = db
                    .query_row(
                        "SELECT COUNT(*) FROM events WHERE session_key=?1 AND tool_id=?2",
                        rusqlite::params![text(&params, "session_key")?, text(&params, "tool_id")?],
                        |v| v.get(0),
                    )
                    .map_err(|e| e.to_string())?;
                if count == 0 {
                    return Err("Feedback command is no longer retained".into());
                }
                if let Some(severity) = params["severity"].as_str()
                    && !["safe", "low", "medium", "high", "critical", "unknown"].contains(&severity)
                {
                    return Err("Invalid feedback severity".into());
                }
                db.execute("INSERT INTO feedback(session_key,tool_id,kind,severity,note,timestamp) VALUES(?1,?2,?3,?4,?5,?6)",rusqlite::params![text(&params,"session_key")?,text(&params,"tool_id")?,kind,params["severity"].as_str(),distill_core::privacy::redact(note),now()]).map_err(|e|e.to_string())?;
                db.execute("DELETE FROM feedback WHERE id IN(SELECT id FROM feedback ORDER BY id DESC LIMIT -1 OFFSET ?1)",[self.config.service.max_events as i64]).map_err(|e|e.to_string())?;
                Ok(json!({"recorded":true,"changes_policy":false}))
            }
            "purge" => {
                let root = params["root"].as_str().map(Path::new);
                if root.is_some_and(|v| !v.is_absolute()) {
                    return Err("Purge root must be absolute".into());
                }
                if root.is_none() && params["all"] != true {
                    return Err("Purge requires root or explicit all=true".into());
                }
                let locked = self.db.lock().map_err(|_| "History unavailable")?;
                let db = locked.as_ref().ok_or("Persistent history is disabled")?;
                let mut stmt = db
                    .prepare("SELECT DISTINCT session_key,cwd FROM events")
                    .map_err(|e| e.to_string())?;
                let keys: Vec<String> = stmt
                    .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))
                    .map_err(|e| e.to_string())?
                    .filter_map(Result::ok)
                    .filter(|(_, cwd)| root.is_none_or(|v| Path::new(cwd).starts_with(v)))
                    .map(|v| v.0)
                    .collect();
                drop(stmt);
                for key in &keys {
                    db.execute("DELETE FROM events WHERE session_key=?1", [key])
                        .map_err(|e| e.to_string())?;
                    db.execute("DELETE FROM feedback WHERE session_key=?1", [key])
                        .map_err(|e| e.to_string())?;
                }
                db.execute_batch("PRAGMA wal_checkpoint(TRUNCATE); VACUUM;")
                    .map_err(|e| e.to_string())?;
                Ok(json!({"sessions_purged":keys.len()}))
            }
            "stats" => {
                let locked = self.db.lock().map_err(|_| "History unavailable")?;
                let db = locked.as_ref().ok_or("Persistent history is disabled")?;
                let count: i64 = db
                    .query_row("SELECT COUNT(*) FROM events", [], |r| r.get(0))
                    .map_err(|e| e.to_string())?;
                let feedback: i64 = db
                    .query_row("SELECT COUNT(*) FROM feedback", [], |r| r.get(0))
                    .map_err(|e| e.to_string())?;
                Ok(
                    json!({"events":count,"feedback":feedback,"retention_days":self.config.history.retention_days,"scope":"Retained observations, not accuracy"}),
                )
            }
            "judge" => self.judge(params),
            "judge_enqueue" => self.enqueue(params),
            "judge_results" => self.advice_results(params),
            "stop" => {
                self.stop.store(true, Ordering::SeqCst);
                Ok(json!({"stopping":true}))
            }
            _ => Err("Unsupported service method".into()),
        }
    }

    fn judge(&self, params: Value) -> Result<Value, String> {
        if self.config.judge.review_format == distill_core::ReviewFormat::Severity {
            let remaining = params["remaining_ms"]
                .as_u64()
                .unwrap_or(0)
                .min(self.config.judge.deadline_ms);
            return self
                .judge_severities(&[params], Duration::from_millis(remaining))?
                .pop()
                .ok_or_else(|| "Missing severity result".into());
        }
        self.judge_with_deadline(params, false)
    }

    fn judge_with_deadline(&self, mut params: Value, background: bool) -> Result<Value, String> {
        if params["model_policy_digest"] != self.config.model_digest() {
            return Err(
                "Model policy changed; restart the optional service before remote analysis".into(),
            );
        }
        if !self.config.judge.enabled {
            return Err("LLM router is disabled; assessments use static analysis only".into());
        }
        let remaining = params["remaining_ms"]
            .as_u64()
            .unwrap_or(0)
            .min(if background {
                self.config.judge.background_deadline_ms
            } else {
                self.config.judge.deadline_ms
            });
        if remaining < 20 {
            return Err("Insufficient model deadline".into());
        }
        let object = params
            .as_object_mut()
            .ok_or("Judge parameters must be an object")?;
        // Local routing/cache provenance is verified above and bound again in
        // the cache key. Opaque model-dependent hashes must not change prompts.
        for field in ["remaining_ms", "model_policy_digest", "policy_digest"] {
            object.remove(field);
        }
        if !self.config.judge.send_script_contents {
            params.as_object_mut().unwrap().remove("scripts");
        }
        if params.to_string().len() > 65536 {
            return Err("Judge payload exceeds limit".into());
        }
        distill_core::privacy::redact_value(&mut params);
        if let Some((model, digest)) = &self.classifier {
            let programs: std::collections::BTreeSet<_> = params["graph"]["nodes"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(|v| v["program"].as_str())
                .collect();
            let gaps: std::collections::BTreeSet<_> = params["coverage_gaps"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(|v| v["code"].as_str())
                .collect();
            let effects: std::collections::BTreeSet<_> = params["effects"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(|v| v["kind"].as_str())
                .collect();
            let signature =
                json!({"programs":programs,"gap_codes":gaps,"effect_kinds":effects}).to_string();
            if let Some(bucket) = model["buckets"].as_array().into_iter().flatten().find(|v| {
                v["signature"].as_str() == Some(&signature)
                    && v["support"]
                        .as_u64()
                        .is_some_and(|v| v >= self.config.service.classifier_min_support as u64)
                    && v["probability"]
                        .as_f64()
                        .is_some_and(|v| v >= self.config.service.classifier_min_probability)
            }) {
                return Ok(
                    json!({"status":"advisory","model":"local-feature-table-v1","prompt_version":"not_applicable","cached":false,"proposal":{"effects":[],"intent_match":"unavailable","explanation":"Local classifier suggestion from reviewed feature buckets. Static uncertainty and authorization requirements are retained."},"classifier":{"severity":bucket["severity"],"support":bucket["support"],"probability":bucket["probability"],"model_sha256":digest}}),
                );
            }
        }
        let key = distill_core::sha256(
            json!([params, self.config.digest(), "judge-prompt-2"])
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
            let mut v = value.clone();
            v["cached"] = json!(true);
            return Ok(v);
        }
        let schema = json!({"type":"object","additionalProperties":false,"properties":{"effects":{"type":"array","items":{"type":"object","additionalProperties":false,"properties":{"kind":{"type":"string","enum":["file_read","file_write","file_delete","execute","connect","privilege","persistence"]},"target":{"type":["string","null"]},"recursive":{"type":"boolean"}},"required":["kind","target","recursive"]}},"intent_match":{"type":"string","enum":["match","partial","mismatch","unavailable"]},"explanation":{"type":"string"}},"required":["effects","intent_match","explanation"]});
        let _permit = self.requests.acquire()?;
        let request = providers::request(
            &self.client,
            &self.config.judge,
            &params,
            &schema,
            self.credential.key(),
        )?
        .timeout(Duration::from_millis(remaining));
        let response = request.send().map_err(providers::transport_error)?;
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
        let content = providers::response_text(self.config.judge.provider, &response)?;
        let mut proposal: Value =
            serde_json::from_str(&content).map_err(|_| "Model proposal is not JSON")?;
        validate_proposal(&proposal)?;
        distill_core::privacy::redact_value(&mut proposal);
        let mut result = json!({"status":"advisory","proposal":proposal,"model":self.config.judge.model,"provider":self.config.judge.provider,"prompt_version":"2","cached":false,"request_digest":key});
        if let Some(source) = params.get("source_review") {
            result["source_review"] = source.clone();
        }
        let mut cache = self.cache.lock().map_err(|_| "Cache unavailable")?;
        if cache.len() >= 256 {
            cache.clear();
        }
        cache.insert(key, (Instant::now(), result.clone()));
        Ok(result)
    }
}

fn validate_proposal(value: &Value) -> Result<(), String> {
    let object = value.as_object().ok_or("Proposal must be an object")?;
    if object.len() != 3
        || !object.contains_key("effects")
        || !object.contains_key("intent_match")
        || !object.contains_key("explanation")
        || value["explanation"].as_str().is_none_or(|v| v.len() > 4096)
        || !matches!(
            value["intent_match"].as_str(),
            Some("match" | "partial" | "mismatch" | "unavailable")
        )
    {
        return Err("Invalid model proposal schema".into());
    }
    let effects = value["effects"]
        .as_array()
        .filter(|v| v.len() <= 32)
        .ok_or("Invalid model effect count")?;
    for effect in effects {
        let o = effect.as_object().ok_or("Invalid effect")?;
        if o.len() != 3
            || !matches!(
                effect["kind"].as_str(),
                Some(
                    "file_read"
                        | "file_write"
                        | "file_delete"
                        | "execute"
                        | "connect"
                        | "privilege"
                        | "persistence"
                )
            )
            || !effect["recursive"].is_boolean()
            || !(effect["target"].is_null()
                || effect["target"].as_str().is_some_and(|v| v.len() <= 4096))
        {
            return Err("Invalid model effect schema".into());
        }
    }
    Ok(())
}

#[cfg(unix)]
fn serve(
    config: Config,
    owner_pid: Option<i32>,
    credential: distill_core::credentials::ServiceCredential,
) -> Result<(), String> {
    use std::os::{
        fd::AsRawFd,
        unix::{fs::PermissionsExt, net::UnixListener},
    };
    if owner_pid.is_some_and(|pid| pid <= 1 || unsafe { libc::kill(pid, 0) } != 0) {
        return Err("Editor host has exited".into());
    }
    if !config.service.history_enabled && !config.judge.enabled {
        return Err(
            "Enable persistent history or the optional judge in user configuration first".into(),
        );
    }
    let dir = service_ipc::directory(&config)?;
    distill_core::integrity::private_directory(&dir)?;
    if service_ipc::request(&config, "hello", json!({}), Duration::from_millis(50)).is_ok() {
        return Err("Service is already running".into());
    }
    let lock = dir.join("service.lock");
    let mut options = fs::OpenOptions::new();
    use std::os::unix::fs::OpenOptionsExt;
    options.write(true).create_new(true).mode(0o600);
    if lock.exists() {
        let bytes = distill_core::integrity::read_private(&lock, 128)?;
        let pid = std::str::from_utf8(&bytes)
            .ok()
            .and_then(|v| v.trim().parse::<i32>().ok())
            .filter(|v| *v > 1)
            .ok_or("Invalid service lock; inspect it before removing")?;
        if unsafe { libc::kill(pid, 0) } == 0 {
            return Err("Another service owns the lock".into());
        }
        fs::remove_file(&lock).map_err(|e| e.to_string())?;
    }
    let mut lock_file = options.open(&lock).map_err(|e| e.to_string())?;
    write!(lock_file, "{}", std::process::id()).map_err(|e| e.to_string())?;
    struct Cleanup(Vec<PathBuf>);
    impl Drop for Cleanup {
        fn drop(&mut self) {
            for p in &self.0 {
                let _ = fs::remove_file(p);
            }
        }
    }
    let socket = dir.join("daemon.sock");
    let endpoint = dir.join("endpoint.json");
    let _cleanup = Cleanup(vec![socket.clone(), endpoint.clone(), lock]);
    if socket.exists() {
        fs::remove_file(&socket).map_err(|e| e.to_string())?;
    }
    let listener = UnixListener::bind(&socket).map_err(|e| e.to_string())?;
    fs::set_permissions(&socket, fs::Permissions::from_mode(0o600)).map_err(|e| e.to_string())?;
    listener.set_nonblocking(true).map_err(|e| e.to_string())?;
    let mut random = [0u8; 32];
    fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut random))
        .map_err(|e| e.to_string())?;
    let token = distill_core::sha256(&random);
    providers::endpoint(&config.judge)?;
    let client = reqwest::blocking::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .retry(reqwest::retry::never())
        .connect_timeout(Duration::from_millis(1000))
        .timeout(Duration::from_millis(config.judge.background_deadline_ms))
        .build()
        .map_err(|_| "Could not initialize judge HTTPS client")?;
    let classifier = if let Some(path) = &config.service.classifier_path
        && config.judge.enabled
    {
        let bytes = distill_core::integrity::read_private(path, 1024 * 1024)?;
        let value: Value = serde_json::from_slice(&bytes).map_err(|_| "Invalid classifier JSON")?;
        if value["schema_version"] != 1
            || value["feature_scheme"] != "ir-gaps-effects-v1"
            || value["reviewed_labels"] != true
            || value["advisory_only"] != true
            || value["validation"]["held_out"].as_u64().unwrap_or(0) == 0
            || value["validation"]["dangerous_false_low_predictions"]
                .as_array()
                .is_none_or(|v| !v.is_empty())
            || value["buckets"].as_array().is_none_or(|v| v.len() > 10000)
        {
            return Err("Classifier lacks reviewed labels, held-out validation, or bounded supported features".into());
        }
        Some((value, distill_core::sha256(&bytes)))
    } else {
        None
    };
    let app = Arc::new(App {
        db: Mutex::new(database(&config, &dir)?),
        client,
        config,
        cache: Mutex::new(BTreeMap::new()),
        stop: AtomicBool::new(false),
        classifier,
        jobs: Mutex::new(background::Jobs::default()),
        credential,
        requests: concurrency::Requests::default(),
    });
    if app.config.service.history_enabled
        && let Ok(entries) = fs::read_dir(dir.join("spool"))
    {
        for entry in entries.take(256).flatten() {
            if let Ok(bytes) =
                distill_core::integrity::read_private(&entry.path(), service_ipc::MAX_MESSAGE)
                && let Ok(event) = serde_json::from_slice(&bytes)
                && app.record(event).is_ok()
            {
                let _ = fs::remove_file(entry.path());
            }
        }
    }
    let bytes=json!({"v":1,"socket":socket,"token":token,"pid":std::process::id(),"history_enabled":app.config.service.history_enabled,"judge_enabled":app.config.judge.enabled}).to_string();
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true).mode(0o600);
    let tmp = dir.join(format!("endpoint-{}.tmp", std::process::id()));
    options
        .open(&tmp)
        .and_then(|mut f| f.write_all(bytes.as_bytes()))
        .map_err(|e| e.to_string())?;
    fs::rename(tmp, &endpoint).map_err(|e| e.to_string())?;
    let active = Arc::new(AtomicUsize::new(0));
    while !app.stop.load(Ordering::SeqCst) {
        if owner_pid.is_some_and(|pid| unsafe { libc::kill(pid, 0) } != 0) {
            break;
        }
        match listener.accept() {
            Ok((mut stream, _)) => {
                if active.load(Ordering::SeqCst) >= 8 {
                    continue;
                }
                active.fetch_add(1, Ordering::SeqCst);
                let app = app.clone();
                let token = token.clone();
                let active = active.clone();
                std::thread::spawn(move || {
                    let result = (|| -> Result<Value, String> {
                        service_ipc::verify_peer(stream.as_raw_fd())?;
                        // BSD/macOS may inherit O_NONBLOCK from the listener.
                        // Large source payloads can arrive in multiple reads;
                        // EAGAIN must not be mistaken for a malformed request.
                        stream.set_nonblocking(false).map_err(|e| e.to_string())?;
                        stream
                            .set_read_timeout(Some(Duration::from_millis(900)))
                            .map_err(|e| e.to_string())?;
                        stream
                            .set_write_timeout(Some(Duration::from_millis(900)))
                            .map_err(|e| e.to_string())?;
                        let mut bytes = Vec::new();
                        let read_started = Instant::now();
                        loop {
                            let remaining = Duration::from_millis(900)
                                .checked_sub(read_started.elapsed())
                                .ok_or("Service request deadline exhausted")?;
                            stream
                                .set_read_timeout(Some(remaining))
                                .map_err(|e| e.to_string())?;
                            let mut chunk = [0; 8192];
                            let n = stream.read(&mut chunk).map_err(|e| e.to_string())?;
                            if n == 0 {
                                return Err("Incomplete request".into());
                            }
                            bytes.extend_from_slice(&chunk[..n]);
                            if bytes.len() > service_ipc::MAX_MESSAGE {
                                return Err("Request exceeds limit".into());
                            }
                            if bytes.contains(&b'\n') {
                                break;
                            }
                        }
                        let request: Value =
                            serde_json::from_slice(&bytes).map_err(|_| "Invalid request JSON")?;
                        let supplied = request["token"].as_str().unwrap_or("");
                        let difference = supplied
                            .bytes()
                            .zip(token.bytes())
                            .fold(0, |v, (a, b)| v | (a ^ b));
                        if request["v"] != 1 || supplied.len() != token.len() || difference != 0 {
                            return Err("Unauthorized service request".into());
                        }
                        app.handle(text(&request, "method")?, request["params"].clone())
                    })();
                    let response = match result {
                        Ok(v) => json!({"ok":true,"result":v}),
                        Err(e) => json!({"ok":false,"error":e}),
                    };
                    let _ = writeln!(stream, "{response}");
                    active.fetch_sub(1, Ordering::SeqCst);
                });
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(10))
            }
            Err(error) => return Err(error.to_string()),
        }
    }
    Ok(())
}

fn main() {
    let args = Args::parse();
    let result = Config::load(args.config.as_deref()).and_then(|config| {
        let credential = if args.credential_stdin {
            distill_core::credentials::ServiceCredential::read(
                std::io::stdin().lock(),
                &config.judge,
            )?
        } else {
            distill_core::credentials::ServiceCredential::from_environment(&config.judge)?
        };
        #[cfg(unix)]
        {
            serve(config, args.owner_pid, credential)
        }
        #[cfg(not(unix))]
        {
            let _ = config;
            Err("Service requires Unix".into())
        }
    });
    if let Err(error) = result {
        eprintln!("distill-service: {error}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn model_schema_rejects_untrusted_fields_and_oversized_effects() {
        assert!(validate_proposal(&json!({"effects":[],"intent_match":"unavailable","explanation":"No established intent"})).is_ok());
        for value in [
            json!({"effects":[],"intent_match":"match","explanation":"x","allow":true}),
            json!({"effects":[{"kind":"file_delete","target":"/","recursive":"true"}],"intent_match":"match","explanation":"x"}),
        ] {
            assert!(validate_proposal(&value).is_err());
        }
    }
}
