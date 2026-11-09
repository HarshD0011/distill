//! Read-only context observations. Environment names are hints, not proof of the
//! execution environment, authorization, recoverability, or a harmless target.
use crate::Analyzer;
use distill_core::ContextEvidence;
impl Analyzer<'_> {
    pub(super) fn context_evidence(&mut self, command: &str) {
        let Some(cwd) = self.cwd.clone() else { return };
        for root in cwd.ancestors().take(32) {
            let git = root.join(".git");
            let dir = if git.is_dir() {
                Some(git)
            } else if git.is_file() {
                self.inspect_read(&git, 4096)
                    .ok()
                    .and_then(|v| v.trim().strip_prefix("gitdir: ").map(|v| root.join(v)))
            } else {
                None
            };
            if let Some(dir) = dir {
                for (source, file) in [
                    ("git.head", dir.join("HEAD")),
                    ("git.remote_default", dir.join("refs/remotes/origin/HEAD")),
                ] {
                    if file.is_file()
                        && let Ok(value) = self.inspect_read(&file, 4096)
                    {
                        self.context_evidence.push(ContextEvidence {
                            source: source.into(),
                            value: Some(distill_core::privacy::redact(value.trim())),
                            status: "observed_file; does not establish clean worktree".into(),
                        });
                    }
                }
                break;
            }
        }
        let words = distill_parse::lex(command)
            .unwrap_or_default()
            .into_iter()
            .filter_map(|v| {
                if let distill_parse::Token::Word(w) = v {
                    Some(w)
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();
        let cloud = words.iter().any(|v| {
            matches!(
                v.text.rsplit('/').next(),
                Some(
                    "aws" | "gcloud" | "az" | "kubectl" | "terraform" | "pulumi" | "psql" | "mysql"
                )
            )
        });
        if !cloud {
            return;
        }
        for (i, word) in words.iter().enumerate() {
            if word.dynamic {
                continue;
            }
            let (flag, value) = word.text.split_once('=').map_or(
                (
                    word.text.as_str(),
                    words
                        .get(i + 1)
                        .filter(|v| !v.dynamic)
                        .map(|v| v.text.as_str()),
                ),
                |(a, b)| (a, Some(b)),
            );
            if matches!(
                flag,
                "--profile" | "--context" | "--project" | "--cluster" | "--host" | "-h"
            ) {
                self.context_evidence.push(ContextEvidence {
                    source: format!("explicit_argument:{flag}"),
                    value: value.map(distill_core::privacy::redact),
                    status: "declared_target; production identity not independently verified"
                        .into(),
                });
            }
        }
        for name in ["AWS_PROFILE", "GOOGLE_CLOUD_PROJECT", "PGHOST"] {
            if let Ok(value) = std::env::var(name)
                && value.len() <= 256
            {
                self.context_evidence.push(ContextEvidence {
                    source: format!("analyzer_environment:{name}"),
                    value: Some(distill_core::privacy::redact(&value)),
                    status: "hint_only; not an execution environment snapshot".into(),
                });
            }
        }
    }
}
