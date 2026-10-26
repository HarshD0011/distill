use distill_parse::Word;

use crate::Analyzer;

const SCRIPT_CAP: usize = 256 * 1024;

impl Analyzer<'_> {
    /// Bounded static expansion for npm/pnpm/yarn scripts and simple Makefiles.
    /// Returns true when this command is one of those wrappers.
    pub(super) fn expand_wrapper(&mut self, name: &str, args: &[Word], depth: usize) -> bool {
        match name {
            "npm" | "pnpm" | "yarn" => self.expand_package_script(name, args, depth),
            "make" => self.expand_make(args, depth),
            _ => false,
        }
    }

    fn expand_package_script(&mut self, name: &str, args: &[Word], depth: usize) -> bool {
        let script_name = package_script_name(name, args);
        self.context_partial = true;
        self.unknown("Package-manager lifecycle hooks and dependency scripts are unresolved");
        self.raise(distill_core::Severity::Medium);
        let installing = args.first().is_some_and(|word| {
            matches!(
                word.text.as_str(),
                "install" | "i" | "ci" | "add" | "update" | "upgrade" | "rebuild" | "publish"
            )
        }) || name == "yarn" && args.is_empty();
        if installing {
            self.finding(
                distill_core::Severity::High,
                distill_core::EffectKind::Execute,
                "exec.package-lifecycle",
                "Package installation may execute dependency and lifecycle code",
            );
        }
        let Some(cwd) = self.cwd.clone() else {
            self.unknown("Working directory is required to read package.json");
            return true;
        };
        let path = cwd.join("package.json");
        match self.inspect_read(&path, SCRIPT_CAP) {
            Ok(text) => {
                if installing {
                    for name in ["preinstall", "install", "postinstall", "prepare"] {
                        if let Some(script) = package_script(&text, name) {
                            self.analyze(&script, depth + 1);
                        }
                    }
                } else if let Some(script_name) = script_name {
                    for name in [
                        format!("pre{script_name}"),
                        script_name.clone(),
                        format!("post{script_name}"),
                    ] {
                        if let Some(script) = package_script(&text, &name) {
                            self.analyze(&script, depth + 1);
                        }
                    }
                }
            }
            Err(error) => self.unknown(&error),
        }
        let lock = cwd.join("package-lock.json");
        if lock.is_file() {
            match self.inspect_read(&lock, SCRIPT_CAP) {
                Ok(text) => {
                    if serde_json::from_str::<serde_json::Value>(&text)
                        .ok()
                        .and_then(|v| {
                            v.get("packages").and_then(|p| p.as_object()).map(|p| {
                                p.values().any(|v| {
                                    v.get("hasInstallScript") == Some(&serde_json::json!(true))
                                })
                            })
                        })
                        .unwrap_or(false)
                    {
                        self.finding(
                            distill_core::Severity::High,
                            distill_core::EffectKind::Execute,
                            "exec.dependency-install-script",
                            "Lockfile identifies dependencies with install scripts",
                        );
                    }
                }
                Err(reason) => self.unknown(&reason),
            }
        }
        true
    }
}

fn package_script_name(tool: &str, args: &[Word]) -> Option<String> {
    let texts: Vec<&str> = args.iter().map(|arg| arg.text.as_str()).collect();
    match tool {
        "npm" | "pnpm" => {
            let rest = texts
                .strip_prefix(&["run"])
                .or_else(|| texts.strip_prefix(&["run-script"]))?;
            rest.first()
                .filter(|name| !name.starts_with('-'))
                .map(|name| (*name).to_string())
        }
        "yarn" => {
            if texts.first() == Some(&"run") {
                texts
                    .get(1)
                    .filter(|name| !name.starts_with('-'))
                    .map(|name| (*name).to_string())
            } else {
                texts
                    .first()
                    .filter(|name| !name.starts_with('-'))
                    .map(|name| (*name).to_string())
            }
        }
        _ => None,
    }
}

fn package_script(json: &str, name: &str) -> Option<String> {
    let value: serde_json::Value = serde_json::from_str(json).ok()?;
    value
        .pointer("/scripts")?
        .get(name)?
        .as_str()
        .map(str::to_string)
}
