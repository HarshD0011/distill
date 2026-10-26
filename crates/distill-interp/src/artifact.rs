//! Bounded literal extraction, with explicit unresolved coverage for the rest of each language.
use crate::Analyzer;
use distill_core::{EffectKind, Severity};
use distill_parse::Word;
impl Analyzer<'_> {
    pub(super) fn artifact_file(&mut self, format: &str, file: &Word, depth: usize) {
        self.unresolved_program("Artifact analysis covers literal instructions only; interpolation, plugins, and surrounding execution remain unresolved");
        let Some(path) = self.lexical_path(file) else {
            self.unknown("Artifact path is unresolved");
            return;
        };
        let source = match self.inspect_read(&path, 64 * 1024) {
            Ok(source) => source,
            Err(reason) => {
                self.unknown(&reason);
                return;
            }
        };
        match format {
            "dockerfile" => {
                let joined = source.replace("\\\n", " ");
                for line in joined.lines() {
                    if !self.within_budget() {
                        break;
                    }
                    let line = line.trim();
                    if line.is_empty() || line.starts_with('#') {
                        continue;
                    }
                    let (instruction, value) =
                        line.split_once(char::is_whitespace).unwrap_or((line, ""));
                    match instruction.to_ascii_uppercase().as_str() {
                        "RUN" => {
                            if value.trim_start().starts_with('[') {
                                if let Ok(argv) = serde_json::from_str::<Vec<String>>(value) {
                                    let command = argv
                                        .iter()
                                        .map(|word| format!("'{}'", word.replace('\'', "'\"'\"'")))
                                        .collect::<Vec<_>>()
                                        .join(" ");
                                    self.analyze(&command, depth + 1);
                                }
                            } else {
                                self.analyze(value, depth + 1);
                            }
                        }
                        "ADD" if value.contains("https://") || value.contains("http://") => self
                            .finding(
                                Severity::High,
                                EffectKind::NetworkReceive,
                                "artifact.remote-add",
                                "Container build fetches remote source",
                            ),
                        "COPY" | "ADD" if crate::is_sensitive(value) => self.finding(
                            Severity::High,
                            EffectKind::FileRead,
                            "artifact.secret-copy",
                            "Container build references credential-like source paths",
                        ),
                        "SHELL" | "ONBUILD" => {
                            self.unknown("Container shell or deferred instruction is unresolved")
                        }
                        _ => {}
                    }
                }
            }
            "ci" => {
                let lines = source.lines().collect::<Vec<_>>();
                let mut index = 0;
                while let Some(line) = lines.get(index) {
                    if !self.within_budget() {
                        break;
                    }
                    index += 1;
                    let indent = line.len() - line.trim_start().len();
                    let trimmed = line
                        .trim_start()
                        .strip_prefix("- ")
                        .unwrap_or(line.trim_start());
                    if let Some(run) = trimmed.strip_prefix("run:") {
                        let run = run.trim();
                        let mut script = String::new();
                        if run.starts_with('|') || run.starts_with('>') {
                            while let Some(line) = lines.get(index).filter(|line| {
                                line.trim().is_empty()
                                    || line.len() - line.trim_start().len() > indent
                            }) {
                                script.push_str(line.trim_start());
                                script.push(if run.starts_with('>') { ' ' } else { '\n' });
                                index += 1;
                            }
                        } else if run.starts_with('"') {
                            if let Ok(value) = serde_json::from_str::<String>(run) {
                                script = value;
                            }
                        } else if let Some(value) =
                            run.strip_prefix('\'').and_then(|v| v.strip_suffix('\''))
                        {
                            script = value.replace("''", "'");
                        } else {
                            script = run.into();
                        }
                        if script.contains("${{") || script.contains("&") {
                            self.unknown(
                                "CI interpolation or YAML semantics can change the recipe",
                            );
                        }
                        if !script.is_empty() {
                            self.analyze(&script, depth + 1);
                        }
                    } else if trimmed.starts_with("uses:") {
                        self.finding(
                            Severity::High,
                            EffectKind::Execute,
                            "artifact.ci-action",
                            "CI workflow executes an external or repository action",
                        );
                    }
                }
            }
            "sql" => self.inspect_sql(
                &source,
                crate::sql::SqlDialect::Unspecified,
                Some(&path.to_string_lossy()),
                1,
            ),
            "awk" => {
                for rest in source.split("system").skip(1) {
                    let rest = rest.trim_start();
                    if let Some(rest) = rest
                        .strip_prefix('(')
                        .map(str::trim_start)
                        .and_then(|rest| rest.strip_prefix('"'))
                        && let Some(end) = rest.find('"')
                        && !rest[..end].contains('\\')
                    {
                        self.analyze(&rest[..end], depth + 1);
                    }
                }
            }
            "sed" => {
                for instruction in source.split(['\n', ';']).map(str::trim) {
                    if let Some(command) = instruction.strip_prefix("e ") {
                        self.analyze(command, depth + 1);
                    }
                    if let Some(path) = instruction.strip_prefix("w ") {
                        self.write_destination(
                            &Word {
                                text: path.into(),
                                dynamic: path.contains('$'),
                                tilde_expansion: false,
                                substitutions: vec![],
                            },
                            true,
                        );
                    }
                }
            }
            _ => self.unknown("Unsupported artifact format"),
        }
    }
}
