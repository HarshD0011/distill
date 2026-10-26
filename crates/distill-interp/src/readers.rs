//! Bounded read profiles: distinguish metadata, file contents and helper execution.
use crate::Analyzer;
use distill_core::{EffectKind, Severity};
use distill_parse::Word;

impl Analyzer<'_> {
    pub(super) fn list_metadata(&mut self, args: &[Word]) {
        self.raise(Severity::Safe);
        let mut options = true;
        for word in args {
            if options && word.text == "--" {
                options = false;
                continue;
            }
            if word.dynamic
                || options
                    && word.text.starts_with('-')
                    && !matches!(word.text.as_str(), "--help" | "--version")
                    && !word.text.strip_prefix('-').is_some_and(|flags| {
                        !flags.is_empty()
                            && flags
                                .chars()
                                .all(|c| "aAbBcCdDfFgGhHiklLmnoOpPqQrRsStTuUvVwWxX1@%".contains(c))
                    })
            {
                self.context_partial = true;
                self.unknown("Directory-listing arguments or options are unresolved");
            }
        }
    }

    pub(super) fn ripgrep(&mut self, args: &[Word]) {
        let mut paths = Vec::new();
        let mut explicit_pattern = false;
        let mut files_only = false;
        let mut options = true;
        let mut pre = None;
        let mut hostname = None;
        let mut decompress = false;
        let mut index = 0;
        while let Some(word) = args.get(index) {
            let text = word.text.as_str();
            if options && text == "--" {
                options = false;
                index += 1;
                continue;
            }
            if options && text.starts_with('-') && text != "-" {
                if word.dynamic {
                    self.unresolved_program("Dynamic search options may select helper execution");
                }
                if matches!(text, "--help" | "-h" | "--version" | "-V") && args.len() == 1 {
                    self.raise(Severity::Safe);
                    return;
                }
                let (flag, inline) = text
                    .split_once('=')
                    .map_or((text, None), |(flag, value)| (flag, Some(value)));
                let short_value = ["-e", "-f", "-g", "-t", "-T", "-A", "-B", "-C", "-m", "-j"]
                    .into_iter()
                    .find(|flag| text.starts_with(flag) && text.len() > flag.len());
                let flag = short_value.unwrap_or(flag);
                let inline = short_value.map(|flag| &text[flag.len()..]).or(inline);
                if [
                    "--pre",
                    "--hostname-bin",
                    "-e",
                    "--regexp",
                    "-f",
                    "--file",
                    "-g",
                    "--glob",
                    "--iglob",
                    "-t",
                    "--type",
                    "-T",
                    "--type-not",
                    "--type-add",
                    "--type-clear",
                    "-A",
                    "--after-context",
                    "-B",
                    "--before-context",
                    "-C",
                    "--context",
                    "-m",
                    "--max-count",
                    "-j",
                    "--threads",
                    "--encoding",
                    "--color",
                    "--colors",
                    "--hyperlink-format",
                    "--pre-glob",
                    "--ignore-file",
                    "--max-depth",
                    "--max-filesize",
                    "--sort",
                    "--sortr",
                ]
                .contains(&flag)
                {
                    let value = if let Some(value) = inline {
                        Some((value, word))
                    } else {
                        index += 1;
                        args.get(index).map(|value| (value.text.as_str(), value))
                    };
                    if let Some((value, source)) = value {
                        if source.dynamic {
                            self.unresolved_program("Search option value is dynamic");
                        }
                        match flag {
                            "--pre" => {
                                pre = Some(value);
                                decompress = false;
                            }
                            "--hostname-bin" => hostname = Some(value),
                            "-e" | "--regexp" => explicit_pattern = true,
                            "-f" | "--file" => {
                                explicit_pattern = true;
                                self.read_destination(&Word {
                                    text: value.into(),
                                    dynamic: source.dynamic,
                                    tilde_expansion: source.tilde_expansion && inline.is_none(),
                                    substitutions: vec![],
                                });
                            }
                            "--ignore-file" => self.read_destination(&Word {
                                text: value.into(),
                                dynamic: source.dynamic,
                                tilde_expansion: source.tilde_expansion && inline.is_none(),
                                substitutions: vec![],
                            }),
                            _ => {}
                        }
                    } else {
                        self.unresolved_program("Search option value is missing");
                    }
                } else if text == "--files" {
                    files_only = true;
                } else if text == "--no-pre" {
                    pre = None;
                } else if matches!(text, "--search-zip" | "-z") {
                    decompress = true;
                    pre = None;
                } else if text == "--no-search-zip" {
                    decompress = false;
                } else if ![
                    "--hidden",
                    "--no-ignore",
                    "--no-ignore-vcs",
                    "--no-config",
                    "--no-heading",
                    "--heading",
                    "--line-number",
                    "--no-line-number",
                    "--with-filename",
                    "--no-filename",
                    "--files-with-matches",
                    "--files-without-match",
                    "--count",
                    "--count-matches",
                    "--only-matching",
                    "--quiet",
                    "--fixed-strings",
                    "--ignore-case",
                    "--case-sensitive",
                    "--smart-case",
                    "--multiline",
                    "--multiline-dotall",
                    "--pcre2",
                    "--text",
                    "--null",
                    "--null-data",
                    "--json",
                    "--stats",
                    "--trim",
                    "--follow",
                    "--no-messages",
                    "--column",
                    "--vimgrep",
                    "--invert-match",
                    "--word-regexp",
                    "--line-regexp",
                ]
                .contains(&text)
                    && !text.strip_prefix('-').is_some_and(|flags| {
                        !flags.is_empty()
                            && flags.chars().all(|c| "nHhilsSuvUowqxFcLaNI0P".contains(c))
                    })
                {
                    self.context_partial = true;
                    self.unknown("Search option is outside the modeled read profile");
                }
            } else {
                paths.push(word);
            }
            index += 1;
        }
        if !files_only && pre.is_some_and(|value| !value.is_empty())
            || hostname.is_some_and(|value| !value.is_empty())
            || !files_only && decompress
        {
            self.finding(Severity::High, EffectKind::Execute, "exec.search-helper", "Search options may launch a preprocessor, hostname provider, or decompressor program");
            self.context_partial = true;
            self.unknown("Search helper executable contents are unresolved");
        }
        if files_only {
            self.raise(Severity::Safe);
            return;
        }
        if !explicit_pattern && !paths.is_empty() {
            paths.remove(0);
        }
        if paths.is_empty() {
            if let Some(cwd) = self.cwd.clone() {
                self.read_destination(&Word {
                    text: cwd.to_string_lossy().into_owned(),
                    dynamic: false,
                    tilde_expansion: false,
                    substitutions: vec![],
                });
            }
            self.context_partial = true;
            self.unknown(
                "Recursive search contents depend on the filesystem and ignore configuration",
            );
        } else {
            for path in paths {
                self.read_destination(path);
                if self.resolve(path).is_some_and(|path| path.is_dir()) {
                    self.context_partial = true;
                    self.unknown("Recursive search contents depend on the filesystem and ignore configuration");
                }
            }
        }
    }
}
