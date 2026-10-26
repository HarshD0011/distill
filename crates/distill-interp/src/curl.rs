use distill_parse::Word;

use crate::Analyzer;

impl Analyzer<'_> {
    pub(super) fn curl(&mut self, args: &[Word]) {
        if is_info_only(args) {
            self.raise(distill_core::Severity::Safe);
            return;
        }
        if self.stream_secret {
            self.finding(
                distill_core::Severity::Critical,
                distill_core::EffectKind::NetworkSend,
                "exfil.secret-to-network",
                "Uploads secret data to the network",
            );
        }
        self.emit_path(&["curl"]);
        let mut index = 0;
        let mut options = true;
        let mut modifier = false;
        while index < args.len() {
            let text = args[index].text.as_str();
            if options && text == "--" {
                options = false;
                index += 1;
                continue;
            }
            if options && text.starts_with("--") {
                self.curl_long(text, args, &mut index, &mut modifier);
            } else if options && text.starts_with('-') && text != "-" {
                self.curl_short(text, args, &mut index, &mut modifier);
            } else {
                if text.contains("://")
                    && text
                        .split("://")
                        .next()
                        .is_some_and(|scheme| scheme.contains('@'))
                {
                    self.emit_path(&["curl", "userinfo"]);
                }
                if is_ip_url(text) {
                    modifier = true;
                }
                index += 1;
            }
        }
        if modifier {
            let bumped = self
                .max_severity
                .unwrap_or(distill_core::Severity::Low)
                .bump(1);
            self.raise(bumped);
            self.finding(
                distill_core::Severity::Medium,
                distill_core::EffectKind::NetworkSend,
                "net.tls-or-ip",
                "TLS verification is disabled or the host is a raw IP",
            );
        }
    }

    fn curl_long(&mut self, text: &str, args: &[Word], index: &mut usize, modifier: &mut bool) {
        let (name, inline) = text[2..]
            .split_once('=')
            .map(|(name, value)| (name, Some(value)))
            .unwrap_or((&text[2..], None));
        let takes_value = CURL_VALUE_OPTIONS.contains(&name);
        let value = if let Some(value) = inline {
            *index += 1;
            Some(value.to_string())
        } else if takes_value {
            *index += 1;
            args.get(*index).map(|word| {
                *index += 1;
                word.text.clone()
            })
        } else {
            *index += 1;
            None
        };
        self.curl_named(name, value.as_deref(), modifier);
    }

    fn curl_short(&mut self, text: &str, args: &[Word], index: &mut usize, modifier: &mut bool) {
        let chars: Vec<char> = text[1..].chars().collect();
        *index += 1;
        for (offset, flag) in chars.iter().enumerate() {
            let last = offset + 1 == chars.len();
            let takes_value = matches!(
                flag,
                'd' | 'F'
                    | 'T'
                    | 'o'
                    | 'X'
                    | 'H'
                    | 'u'
                    | 'b'
                    | 'c'
                    | 'K'
                    | 'x'
                    | 'w'
                    | 'A'
                    | 'e'
                    | 'm'
                    | 'E'
                    | 'P'
                    | 'Q'
                    | 'Y'
            );
            let inline = if !last && takes_value {
                Some(chars[offset + 1..].iter().collect::<String>())
            } else {
                None
            };
            let value = if let Some(inline) = inline {
                Some(inline)
            } else if takes_value && last {
                args.get(*index).map(|word| {
                    *index += 1;
                    word.text.clone()
                })
            } else {
                None
            };
            match flag {
                'd' | 'F' => self.curl_upload(value.as_deref()),
                'T' => {
                    self.curl_upload(value.as_deref().map(|value| format!("@{value}")).as_deref())
                }
                'o' | 'O' => self.curl_output(value.as_deref()),
                'X' => self.curl_method(value.as_deref()),
                'H' => self.curl_header(value.as_deref()),
                'u' | 'b' | 'c' => self.emit_path(&["curl", "secret"]),
                'K' => self.emit_path(&["curl", "config"]),
                'k' => *modifier = true,
                'I' | 's' | 'S' | 'f' | 'v' | 'L' | 'G' | '#' => {}
                _ => {
                    self.context_partial = true;
                    self.unknown("Unmodeled curl short option");
                }
            }
            if takes_value {
                break;
            }
        }
    }

    fn curl_named(&mut self, name: &str, value: Option<&str>, modifier: &mut bool) {
        match name {
            "data" | "data-binary" | "data-urlencode" | "form" => self.curl_upload(value),
            "upload-file" => self.curl_upload(value.map(|value| format!("@{value}")).as_deref()),
            "data-raw" | "form-string" => self.emit_path(&["curl", "upload"]),
            "output" | "remote-name" | "output-dir" | "dump-header" | "trace" | "trace-ascii"
            | "libcurl" | "cookie-jar" => self.curl_output(value),
            "request" => self.curl_method(value),
            "header" => self.curl_header(value),
            "user" | "oauth2-bearer" | "netrc" | "netrc-optional" | "netrc-file" | "cookie" => {
                self.emit_path(&["curl", "secret"]);
            }
            "config" => self.emit_path(&["curl", "config"]),
            "insecure" => *modifier = true,
            "head" | "silent" | "show-error" | "fail" | "verbose" | "location" | "get"
            | "http1.1" | "http2" | "ipv4" | "ipv6" => {}
            "help" | "version" | "manual" => {}
            _ if CURL_KNOWN.contains(&name) => {}
            _ => {
                self.context_partial = true;
                self.unknown("Unmodeled curl option");
            }
        }
    }

    fn curl_upload(&mut self, value: Option<&str>) {
        let file = value
            .and_then(|value| {
                value
                    .strip_prefix('@')
                    .or_else(|| value.split_once("=@").map(|(_, path)| path))
            })
            .map(|value| value.split(';').next().unwrap_or(value));
        if let Some(file) = file {
            let word = Word {
                text: file.into(),
                dynamic: file.contains('$'),
                tilde_expansion: file.starts_with('~'),
                substitutions: Vec::new(),
            };
            self.read_destination(&word);
        }
        if self.read_secret || file.is_some_and(crate::is_sensitive) {
            self.emit_path(&["curl", "upload", "@secret"]);
        } else {
            self.emit_path(&["curl", "upload"]);
        }
    }

    fn curl_output(&mut self, value: Option<&str>) {
        let Some(value) = value else {
            self.emit_path(&["curl", "output"]);
            return;
        };
        let word = Word {
            text: value.trim_start_matches('@').into(),
            dynamic: value.contains('$'),
            tilde_expansion: false,
            substitutions: Vec::new(),
        };
        let path = self.resolve(&word);
        self.record_behavior(
            distill_core::Behavior {
                database: None,
                kind: distill_core::EffectKind::FileWrite,
                operation: "curl.output".into(),
                target: path
                    .as_ref()
                    .map(|path| path.to_string_lossy().into_owned()),
                target_class: self.target_class(path.as_deref()),
                recursive: false,
                append: false,
                location: None,
            },
            None,
        );
        self.last_network_producer = true;
        let class = crate::class::classify(
            &word.text,
            path.as_deref(),
            self.root_or_home(&word.text, path.as_deref()),
        );
        match class {
            crate::class::ArgClass::RootOrHome => {
                self.emit_path(&["curl", "output", "@protected"]);
            }
            crate::class::ArgClass::StartupFile | crate::class::ArgClass::Secret => {
                self.finding(
                    distill_core::Severity::High,
                    distill_core::EffectKind::FileWrite,
                    "write.startup",
                    "Downloads over a file that runs automatically or holds credentials",
                );
            }
            _ => self.emit_path(&["curl", "output"]),
        }
    }

    fn curl_method(&mut self, value: Option<&str>) {
        if value.is_some_and(|value| value.eq_ignore_ascii_case("DELETE")) {
            self.emit_path(&["curl", "DELETE"]);
        }
    }

    fn curl_header(&mut self, value: Option<&str>) {
        let Some(value) = value else {
            return;
        };
        let lower = value.to_ascii_lowercase();
        if lower.starts_with("authorization:")
            || lower.contains("bearer ")
            || lower.starts_with("cookie:")
            || lower.contains("api-key")
            || lower.contains("token")
        {
            self.emit_path(&["curl", "header-secret"]);
        }
    }
}

fn is_info_only(args: &[Word]) -> bool {
    !args.is_empty()
        && args.iter().all(|arg| {
            matches!(
                arg.text.as_str(),
                "--version" | "--help" | "--manual" | "-V" | "-h" | "-M"
            )
        })
}

fn is_ip_url(text: &str) -> bool {
    let host = text
        .split("://")
        .nth(1)
        .unwrap_or(text)
        .trim_start_matches('[')
        .split(['/', ':', ']', '@'])
        .find(|part| !part.is_empty())
        .unwrap_or("");
    let host = host.rsplit('@').next().unwrap_or(host);
    !host.is_empty()
        && host
            .split('.')
            .all(|part| !part.is_empty() && part.chars().all(|ch| ch.is_ascii_digit()))
}

const CURL_VALUE_OPTIONS: &[&str] = &[
    "data",
    "data-raw",
    "data-binary",
    "data-urlencode",
    "form",
    "form-string",
    "upload-file",
    "output",
    "output-dir",
    "dump-header",
    "trace",
    "trace-ascii",
    "libcurl",
    "cookie-jar",
    "request",
    "header",
    "user",
    "oauth2-bearer",
    "netrc-file",
    "cookie",
    "config",
    "url",
    "referer",
    "user-agent",
    "proxy",
    "max-time",
    "connect-timeout",
    "retry",
    "write-out",
];

const CURL_KNOWN: &[&str] = &[
    "url",
    "referer",
    "user-agent",
    "proxy",
    "max-time",
    "connect-timeout",
    "retry",
    "write-out",
    "compressed",
    "fail-with-body",
    "path-as-is",
    "remote-time",
    "create-dirs",
    "continue-at",
    "range",
    "http1.0",
    "tlsv1.2",
    "tlsv1.3",
];
