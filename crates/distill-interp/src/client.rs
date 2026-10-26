//! Client programs route SQL, shell and file roles before language interpretation.
use crate::{
    Analyzer,
    arguments::{self, Role},
    sql::SqlDialect,
};
use distill_core::{
    Behavior, DatabaseAction, DatabaseScope, EffectKind, SourceLocation, TargetClass,
};
use distill_parse::Word;
use serde::Deserialize;
use std::{collections::BTreeMap, sync::OnceLock};

#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum CapabilityKind {
    NativeLoad,
    FileRead,
    FileWrite,
    Shell,
    Script,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct FunctionCapability {
    pub kind: CapabilityKind,
    pub argument: usize,
}
#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum ClientSyntax {
    Rest,
    SqliteJoin,
    SqliteWords,
    PsqlPath,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ClientCapability {
    kind: CapabilityKind,
    syntax: ClientSyntax,
    #[serde(default)]
    pipe: bool,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Catalog {
    version: u32,
    functions: BTreeMap<String, BTreeMap<String, FunctionCapability>>,
    clients: BTreeMap<String, BTreeMap<String, ClientCapability>>,
}
fn catalog() -> &'static Catalog {
    static CATALOG: OnceLock<Catalog> = OnceLock::new();
    CATALOG.get_or_init(|| {
        let catalog: Catalog = serde_json::from_str(include_str!("../rules/languages.json"))
            .expect("valid bundled language capabilities");
        assert_eq!(catalog.version, 1);
        catalog
    })
}
pub(super) fn function_capability(
    dialect: &str,
    name: &str,
) -> Option<&'static FunctionCapability> {
    catalog().functions.get(dialect)?.get(name)
}
fn literal(text: String) -> Word {
    Word {
        text,
        dynamic: false,
        tilde_expansion: false,
        substitutions: vec![],
    }
}
fn dialect(client: &str) -> SqlDialect {
    match client {
        "psql" => SqlDialect::Postgres,
        "sqlite3" => SqlDialect::Sqlite,
        _ => SqlDialect::Mysql,
    }
}

impl Analyzer<'_> {
    pub(super) fn language_capability(
        &mut self,
        kind: CapabilityKind,
        value: Option<String>,
        location: Option<SourceLocation>,
    ) {
        let old_location = self.shell_location.clone();
        if location.is_some() {
            self.shell_location = location.clone();
        }
        match kind {
            CapabilityKind::NativeLoad => {
                self.record_behavior(
                    Behavior {
                        kind: EffectKind::Execute,
                        operation: "native_load".into(),
                        target: value,
                        target_class: TargetClass::Unresolved,
                        recursive: false,
                        append: false,
                        location,
                        database: None,
                    },
                    None,
                );
                self.context_partial = true;
                self.unknown(
                    "Native module contents, loader search and runtime identity are unresolved",
                );
            }
            CapabilityKind::FileRead => self.read_destination(&Word {
                dynamic: value.is_none(),
                ..literal(value.unwrap_or_default())
            }),
            CapabilityKind::FileWrite => self.write_destination(
                &Word {
                    dynamic: value.is_none(),
                    ..literal(value.unwrap_or_default())
                },
                true,
            ),
            _ => self.unresolved_program("Language capability requires a client execution context"),
        }
        self.shell_location = old_location;
    }

    pub(super) fn database_client(&mut self, client: &str, args: &[Word], depth: usize) {
        // The baseline represents database/client state without asserting a pure SELECT proof.
        self.record_behavior(
            Behavior::database(
                DatabaseAction::Query,
                DatabaseScope::Unresolved,
                None,
                self.shell_location.clone(),
            ),
            None,
        );
        self.context_partial = true;
        self.unknown(
            "Database/client schema, startup configuration and runtime state remain unresolved",
        );
        let mut decoded = arguments::decode(client, args, &self.budget);
        if let Some(reason) = decoded.unknown {
            self.unresolved_program(reason);
            if self.budget.expired() {
                self.stop_analysis(self.budget.stop_reason());
            }
        }
        decoded
            .arguments
            .sort_by_key(|arg| (!arg.before_program, arg.index));
        for argument in decoded.arguments {
            if !self.within_budget() {
                break;
            }
            let Some(value) = argument.value else {
                continue;
            };
            match argument.role {
                Role::Read => self.read_destination(&value),
                Role::Write => {
                    if argument.pipe && value.text.starts_with('|') {
                        if value.dynamic {
                            self.unresolved_program("Client output command is dynamic");
                        } else {
                            self.client_shell(&value.text[1..], depth);
                        }
                    } else {
                        self.write_destination(&value, !argument.append);
                    }
                }
                Role::Script => self.client_file(client, &value, depth),
                Role::Program if !value.dynamic => {
                    self.client_program(client, &value.text, false, depth, None)
                }
                Role::Program => self.unresolved_program("Client program text is dynamic"),
                _ => {}
            }
        }
        if client == "sqlite3" {
            // Options are processed before positional SQL; the first operand is the database.
            for program in decoded.operands.iter().skip(1) {
                if program.dynamic {
                    self.unresolved_program("SQLite program text is dynamic");
                } else {
                    self.client_program(client, &program.text, false, depth, None);
                }
            }
        }
    }

    fn client_file(&mut self, client: &str, file: &Word, depth: usize) {
        // File effects survive failure to inspect the source.
        self.read_destination(file);
        if depth >= self.config.analysis.expansion_depth_max {
            self.stop_analysis("Client source recursion limit exhausted");
            return;
        }
        if file.text == "-" {
            self.unresolved_program("Client source depends on standard input");
            return;
        }
        let Some(path) = self.lexical_path(file) else {
            self.unresolved_program("Client source path is unresolved");
            return;
        };
        match self.inspect_read(&path, 64 * 1024) {
            Ok(source) => self.client_program(
                client,
                &source,
                true,
                depth + 1,
                Some(&path.to_string_lossy()),
            ),
            Err(reason) => {
                self.unknown(&reason);
                self.context_partial = true;
            }
        }
    }

    fn client_shell(&mut self, source: &str, depth: usize) {
        // Unix system() uses /bin/sh. Do not inherit the outer user's Zsh grammar/options.
        let cwd = self.cwd.clone();
        let outputs = self.print_outputs.clone();
        let dialect = self.dialect;
        let options = self.shell_options.take();
        self.dialect = distill_core::ShellDialect::Posix;
        self.analyze(source, depth + 1);
        self.cwd = cwd;
        self.print_outputs = outputs;
        self.dialect = dialect;
        self.shell_options = options;
        self.context_partial = true;
        self.unknown("Client shell execution is conditional on client state and platform");
    }

    fn client_program(
        &mut self,
        client: &str,
        source: &str,
        script: bool,
        depth: usize,
        origin: Option<&str>,
    ) {
        if !self.within_budget() {
            return;
        }
        if source.len() > 64 * 1024 {
            self.stop_analysis("Client program exceeds the byte limit");
            return;
        }
        if depth > self.config.analysis.expansion_depth_max {
            self.stop_analysis("Client program recursion limit exhausted");
            return;
        }
        if client == "psql" && !script {
            if source.trim_start().starts_with('\\') {
                self.client_meta(client, source.trim_start(), depth, origin, 1);
            } else {
                self.inspect_sql(source, dialect(client), origin, 1);
            }
            return;
        }
        if client == "mysql" {
            self.inspect_sql(source, dialect(client), origin, 1);
            return;
        }
        let mut state = InputState::default();
        let mut sql = String::new();
        let mut sql_line = 1;
        for (index, line) in source.split_inclusive('\n').enumerate() {
            if !self.within_budget() {
                return;
            }
            let meta = state.normal()
                && ((client == "sqlite3" && !state.pending && line.starts_with('.'))
                    || (client == "psql" && line.trim_start().starts_with('\\')));
            if meta {
                if !sql.trim().is_empty() {
                    self.inspect_sql(&sql, dialect(client), origin, sql_line);
                    sql.clear();
                }
                self.client_meta(
                    client,
                    line.trim_end_matches(['\r', '\n']),
                    depth,
                    origin,
                    index + 1,
                );
                sql_line = index + 2;
            } else {
                if sql.is_empty() {
                    sql_line = index + 1;
                }
                sql.push_str(line);
                state.line(line, client == "psql");
                if state.normal() && !state.pending {
                    self.inspect_sql(&sql, dialect(client), origin, sql_line);
                    sql.clear();
                }
            }
        }
        if !sql.trim().is_empty() {
            self.inspect_sql(&sql, dialect(client), origin, sql_line);
        }
    }

    fn client_meta(
        &mut self,
        client: &str,
        line: &str,
        depth: usize,
        origin: Option<&str>,
        line_number: usize,
    ) {
        let (name, rest) = line.split_once(char::is_whitespace).unwrap_or((line, ""));
        let Some(spec) = catalog().clients.get(client).and_then(|m| m.get(name)) else {
            self.unresolved_program("Client metacommand is outside the reviewed grammar");
            return;
        };
        let rest = rest.trim_start();
        let location = Some(SourceLocation {
            file: origin.map(str::to_owned),
            line: line_number,
            column: 1,
        });
        let value = match spec.syntax {
            ClientSyntax::Rest => {
                if rest.contains('\n') {
                    self.unresolved_program("Multi-line client metacommand has partial coverage");
                }
                Some(rest.lines().next().unwrap_or("").to_owned())
            }
            ClientSyntax::SqliteJoin => sqlite_words(rest).map(|words| {
                words
                    .into_iter()
                    .map(|w| {
                        if w.contains(' ') {
                            format!("\"{w}\"")
                        } else {
                            w
                        }
                    })
                    .collect::<Vec<_>>()
                    .join(" ")
            }),
            ClientSyntax::SqliteWords => {
                sqlite_words(rest).and_then(|words| words.first().cloned())
            }
            ClientSyntax::PsqlPath => {
                if rest.contains(['`', ':', '\\', '\n']) {
                    None
                } else if let Some(quoted) =
                    rest.strip_prefix('\'').and_then(|s| s.strip_suffix('\''))
                {
                    Some(quoted.into())
                } else if rest.split_whitespace().count() == 1 {
                    Some(rest.into())
                } else {
                    None
                }
            }
        };
        match spec.kind {
            CapabilityKind::Shell => {
                if let Some(source) = value {
                    self.client_shell(&source, depth);
                } else {
                    self.unresolved_program("Client shell argument decoding is unresolved");
                }
            }
            CapabilityKind::Script => {
                if let Some(path) = value {
                    if spec.pipe && path.starts_with('|') {
                        self.client_shell(&path[1..], depth);
                        self.unresolved_program(
                            "Commands produced by a client input pipe are unresolved",
                        );
                    } else {
                        self.client_file(client, &literal(path), depth);
                    }
                } else {
                    self.unresolved_program("Client script argument is unresolved");
                }
            }
            CapabilityKind::FileWrite if value.as_ref().is_some_and(|s| s.starts_with('|')) => {
                self.client_shell(&value.unwrap()[1..], depth);
            }
            kind => self.language_capability(kind, value, location),
        }
    }
}

/// SQLite dot arguments use their own quoting; they are not shell words.
fn sqlite_words(source: &str) -> Option<Vec<String>> {
    let chars = source.chars().collect::<Vec<_>>();
    let mut i = 0;
    let mut words = Vec::new();
    while i < chars.len() {
        while chars.get(i).is_some_and(|c| c.is_whitespace()) {
            i += 1;
        }
        if i == chars.len() {
            break;
        }
        let quote = if matches!(chars[i], '\'' | '"') {
            let q = chars[i];
            i += 1;
            Some(q)
        } else {
            None
        };
        let mut value = String::new();
        let mut closed = quote.is_none();
        while let Some(&c) = chars.get(i) {
            i += 1;
            if quote == Some(c) {
                closed = true;
                break;
            }
            if quote.is_none() && c.is_whitespace() {
                break;
            }
            if quote == Some('"') && c == '\\' {
                let escaped = *chars.get(i)?;
                i += 1;
                value.push(match escaped {
                    'n' => '\n',
                    'r' => '\r',
                    't' => '\t',
                    '\\' => '\\',
                    '"' => '"',
                    _ => return None,
                });
            } else {
                value.push(c);
            }
        }
        if !closed {
            return None;
        }
        if quote.is_some() && chars.get(i).is_some_and(|c| !c.is_whitespace()) {
            return None;
        }
        words.push(value);
    }
    Some(words)
}

#[derive(Default)]
struct InputState {
    quote: Option<u8>,
    block: usize,
    dollar: Option<Vec<u8>>,
    pending: bool,
    escaped: bool,
}
impl InputState {
    fn normal(&self) -> bool {
        self.quote.is_none() && self.block == 0 && self.dollar.is_none()
    }
    fn line(&mut self, line: &str, postgres: bool) {
        let b = line.as_bytes();
        let mut i = 0;
        while i < b.len() {
            if let Some(delimiter) = &self.dollar {
                if b[i..].starts_with(delimiter) {
                    i += delimiter.len();
                    self.dollar = None;
                } else {
                    i += 1;
                }
                continue;
            }
            if let Some(q) = self.quote {
                if self.escaped && b[i] == b'\\' {
                    i = (i + 2).min(b.len());
                    continue;
                }
                if b[i] == q {
                    if b.get(i + 1) == Some(&q) {
                        i += 2;
                        continue;
                    }
                    self.quote = None;
                }
                i += 1;
                continue;
            }
            if self.block > 0 {
                if b[i..].starts_with(b"/*") {
                    self.block += 1;
                    i += 2;
                } else if b[i..].starts_with(b"*/") {
                    self.block -= 1;
                    i += 2;
                } else {
                    i += 1;
                }
                continue;
            }
            if b[i..].starts_with(b"--") {
                break;
            }
            if b[i..].starts_with(b"/*") {
                self.block = 1;
                i += 2;
                continue;
            }
            if matches!(b[i], b'\'' | b'"' | b'`') {
                self.quote = Some(b[i]);
                self.escaped =
                    postgres && b[i] == b'\'' && i > 0 && matches!(b[i - 1], b'e' | b'E');
                self.pending = true;
                i += 1;
                continue;
            }
            if postgres && b[i] == b'$' {
                let mut end = i + 1;
                while b
                    .get(end)
                    .is_some_and(|c| c.is_ascii_alphanumeric() || *c == b'_')
                {
                    end += 1;
                }
                if b.get(end) == Some(&b'$') && (end == i + 1 || !b[i + 1].is_ascii_digit()) {
                    self.dollar = Some(b[i..=end].to_vec());
                    self.pending = true;
                    i = end + 1;
                    continue;
                }
            }
            if b[i] == b';' {
                self.pending = false;
            } else if !b[i].is_ascii_whitespace() {
                self.pending = true;
            }
            i += 1;
        }
    }
}
