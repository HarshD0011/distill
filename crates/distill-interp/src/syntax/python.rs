//! Bounded Python values and effects. Never imports modules or executes source.
//! Only values with known builtin provenance may use the supported operations.
use std::collections::HashMap;

use distill_core::EffectKind;
use tree_sitter::Node;

use super::{Observation, children, field_text, text};

fn string_literal(node: Node<'_>, source: &str) -> Option<String> {
    if node.kind() != "string" || children(node).iter().any(|n| n.kind() == "interpolation") {
        return None;
    }
    let raw = text(node, source);
    let start = raw.find(['\'', '"'])?;
    let prefix = raw[..start].to_ascii_lowercase();
    if !matches!(prefix.as_str(), "" | "u" | "r" | "b" | "br" | "rb") {
        return None;
    }
    let mark = &raw[start..start + 1];
    let delimiter = if raw[start..].starts_with(&mark.repeat(3)) {
        mark.repeat(3)
    } else {
        mark.into()
    };
    let content = raw.get(start + delimiter.len()..raw.len().checked_sub(delimiter.len())?)?;
    if content.len() > 4096 {
        return None;
    }
    if prefix.contains('r') {
        return Some(content.into());
    }
    let mut out = String::new();
    let mut chars = content.chars().peekable();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match chars.next()? {
            '\\' => out.push('\\'),
            '\'' => out.push('\''),
            '"' => out.push('"'),
            'n' => out.push('\n'),
            'r' => out.push('\r'),
            't' => out.push('\t'),
            'b' => out.push('\u{8}'),
            'f' => out.push('\u{c}'),
            'a' => out.push('\u{7}'),
            'v' => out.push('\u{b}'),
            '\n' => {}
            '\r' => {
                if chars.peek() == Some(&'\n') {
                    chars.next();
                }
            }
            kind @ ('x' | 'u' | 'U') => {
                let width = match kind {
                    'x' => 2,
                    'u' => 4,
                    _ => 8,
                };
                let digits: String = (0..width).map(|_| chars.next()).collect::<Option<_>>()?;
                out.push(char::from_u32(u32::from_str_radix(&digits, 16).ok()?)?);
            }
            first @ '0'..='7' => {
                let mut digits = String::from(first);
                for _ in 0..2 {
                    if chars.peek().is_some_and(|c| matches!(c, '0'..='7')) {
                        digits.push(chars.next()?);
                    }
                }
                out.push(char::from_u32(u32::from_str_radix(&digits, 8).ok()?)?);
            }
            'N' => return None,
            other => {
                out.push('\\');
                out.push(other);
            }
        }
    }
    Some(out)
}

#[derive(Clone, Debug, PartialEq)]
enum Value {
    Data(Option<String>),
    Boolean(bool),
    Sequence(Vec<Value>),
    Module(String),
    Path(Option<String>),
    File(Option<String>, String),
    Function(usize),
    Process,
    Stream,
    Unknown,
}
impl Value {
    fn data(&self) -> bool {
        match self {
            Self::Data(_) | Self::Boolean(_) | Self::Path(_) | Self::Stream => true,
            Self::Sequence(values) => values.iter().all(Self::data),
            _ => false,
        }
    }
    fn string(&self) -> Option<String> {
        match self {
            Self::Data(value) | Self::Path(value) => value.clone(),
            _ => None,
        }
    }
}
type Env = HashMap<String, Value>;

pub(crate) struct Command {
    pub argv: Vec<String>,
    pub shell: bool,
}
#[derive(Default)]
pub(crate) struct Analysis {
    pub gaps: Vec<String>,
    pub imports: Vec<String>,
    pub commands: Vec<Command>,
    pub observations: Vec<Observation>,
}
struct Walker<'a> {
    source: &'a str,
    budget: &'a distill_core::AnalysisBudget,
    result: Analysis,
    functions: Vec<Node<'a>>,
    depth: usize,
    steps: usize,
}

pub(super) fn analyze<'a>(
    root: Node<'a>,
    source: &'a str,
    budget: &'a distill_core::AnalysisBudget,
) -> Analysis {
    let mut walker = Walker {
        source,
        budget,
        result: Analysis::default(),
        functions: vec![],
        depth: 0,
        steps: 0,
    };
    let mut env = Env::from([("__name__".into(), Value::Data(None))]);
    walker.statement(root, &mut env);
    walker.result
}

fn merge(base: &mut Env, other: &Env) {
    for (name, value) in other {
        if base.get(name) != Some(value) {
            let value = if value.data() && base.get(name).is_some_and(Value::data) {
                Value::Data(None)
            } else {
                Value::Unknown
            };
            base.insert(name.clone(), value);
        }
    }
}

impl<'a> Walker<'a> {
    fn gap(&mut self, message: impl Into<String>) -> Value {
        let message = message.into();
        if !self.result.gaps.contains(&message) {
            self.result.gaps.push(message);
        }
        Value::Unknown
    }
    fn tick(&mut self) -> bool {
        self.steps += 1;
        if self.budget.expired() || !self.budget.visit_node() {
            self.gap("Shared Python analysis budget exhausted");
            return false;
        }
        if self.steps > 8192 || self.depth > 8 {
            self.gap("Python value propagation or function-call limit reached");
            false
        } else {
            true
        }
    }
    fn effect(
        &mut self,
        node: Node<'a>,
        kind: EffectKind,
        call: &str,
        path: Option<String>,
        recursive: bool,
        append: bool,
    ) {
        if path.is_none() {
            self.gap(format!("Python {call} target is unresolved"));
        }
        self.result.observations.push(Observation {
            kind,
            call: call.into(),
            path,
            recursive,
            append,
            line: node.start_position().row + 1,
            column: node.start_position().column + 1,
        });
    }
    fn bind(&mut self, node: Node<'a>, value: Value, env: &mut Env) {
        match node.kind() {
            "identifier" => {
                env.insert(text(node, self.source).into(), value);
            }
            "pattern_list" | "tuple_pattern" | "list_pattern" | "tuple" | "list" => {
                let names = children(node);
                for (index, name) in names.into_iter().enumerate() {
                    let part = match &value {
                        Value::Sequence(values) => {
                            values.get(index).cloned().unwrap_or(Value::Unknown)
                        }
                        v if v.data() => Value::Data(None),
                        _ => Value::Unknown,
                    };
                    self.bind(name, part, env);
                }
            }
            _ => {
                self.gap("Python attribute, subscript, or dynamic assignment is unresolved");
            }
        }
    }
    fn statement(&mut self, node: Node<'a>, env: &mut Env) -> Option<Value> {
        if !self.tick() {
            return None;
        }
        match node.kind() {
            "module" | "block" | "expression_statement" => {
                for child in children(node) {
                    if let Some(value) = self.statement(child, env) {
                        return Some(value);
                    }
                }
            }
            "import_statement" | "import_from_statement" => self.import(node, env),
            "assignment" => {
                if let Some(annotation) = node.child_by_field_name("type") {
                    self.expression(annotation, env);
                }
                if let (Some(left), Some(right)) = (
                    node.child_by_field_name("left"),
                    node.child_by_field_name("right"),
                ) {
                    let value = self.expression(right, env);
                    self.bind(left, value, env);
                } else {
                    self.gap("Python assignment is unresolved");
                }
            }
            "augmented_assignment" => {
                if let (Some(left), Some(right)) = (
                    node.child_by_field_name("left"),
                    node.child_by_field_name("right"),
                ) {
                    let a = self.expression(left, env);
                    let b = self.expression(right, env);
                    let value = if a.data() && b.data() {
                        Value::Data(None)
                    } else {
                        self.gap("Python augmented assignment may invoke user code")
                    };
                    self.bind(left, value, env);
                }
            }
            "assert_statement" | "raise_statement" => {
                for child in children(node) {
                    let value = self.expression(child, env);
                    if !value.data() {
                        self.gap("Python assertion or exception value is unresolved");
                    }
                }
            }
            "return_statement" => {
                return Some(
                    children(node)
                        .first()
                        .map(|n| self.expression(*n, env))
                        .unwrap_or(Value::Data(None)),
                );
            }
            "function_definition" => {
                let params = node.child_by_field_name("parameters")?;
                // Defaults and annotations execute at definition time.
                for param in children(params) {
                    if param.kind() != "identifier" {
                        self.gap("Python decorated, annotated, or variadic function parameters are unresolved");
                        for child in children(param) {
                            self.expression(child, env);
                        }
                    }
                }
                if node.child_by_field_name("return_type").is_some() {
                    self.gap("Python function return annotation is unresolved");
                }
                if let Some(name) = field_text(node, "name", self.source) {
                    self.functions.push(node);
                    env.insert(name.into(), Value::Function(self.functions.len() - 1));
                }
            }
            "if_statement" => {
                if let Some(condition) = node.child_by_field_name("condition") {
                    let v = self.expression(condition, env);
                    if !v.data() {
                        self.gap("Python condition may invoke user code");
                    }
                }
                let base = env.clone();
                for child in children(node)
                    .into_iter()
                    .filter(|n| Some(*n) != node.child_by_field_name("condition"))
                {
                    let mut branch = base.clone();
                    self.statement(child, &mut branch);
                    merge(env, &branch);
                }
            }
            "else_clause" | "elif_clause" => {
                for child in children(node) {
                    self.statement(child, env);
                }
            }
            "for_statement" => {
                let (Some(left), Some(right), Some(body)) = (
                    node.child_by_field_name("left"),
                    node.child_by_field_name("right"),
                    node.child_by_field_name("body"),
                ) else {
                    self.gap("Python loop is unresolved");
                    return None;
                };
                let value = self.expression(right, env);
                let items = match value {
                    Value::Sequence(v) if v.len() <= 32 => v,
                    v if v.data() => vec![Value::Data(None)],
                    _ => {
                        self.gap("Python iterator may invoke user code");
                        vec![Value::Unknown]
                    }
                };
                let mut local = env.clone();
                for value in items {
                    self.bind(left, value, &mut local);
                    self.statement(body, &mut local);
                }
                merge(env, &local);
                if let Some(other) = node.child_by_field_name("alternative") {
                    self.statement(other, env);
                }
            }
            "with_statement" => {
                for clause in children(node) {
                    if clause.kind() == "with_clause" {
                        for item in children(clause) {
                            let Some(value) = item.child_by_field_name("value") else {
                                self.gap("Python context manager is unresolved");
                                continue;
                            };
                            let (expression, alias) = if value.kind() == "as_pattern" {
                                (
                                    children(value).first().copied().unwrap_or(value),
                                    value.child_by_field_name("alias"),
                                )
                            } else {
                                (value, None)
                            };
                            let resource = self.expression(expression, env);
                            if !matches!(resource, Value::File(_, _)) {
                                self.gap("Python context manager may execute user code");
                            }
                            if let Some(alias) = alias {
                                let alias = children(alias).first().copied().unwrap_or(alias);
                                self.bind(alias, resource, env);
                            }
                        }
                    } else {
                        self.statement(clause, env);
                    }
                }
            }
            "pass_statement" | "break_statement" | "continue_statement" => {}
            "class_definition"
            | "decorated_definition"
            | "try_statement"
            | "while_statement"
            | "global_statement"
            | "nonlocal_statement"
            | "delete_statement" => {
                self.gap(format!(
                    "Python {} requires additional execution semantics",
                    node.kind()
                ));
                // The separate conditional effect collector still visits all bodies.
            }
            _ => {
                self.expression(node, env);
            }
        }
        None
    }
    fn import(&mut self, node: Node<'a>, env: &mut Env) {
        let module = field_text(node, "module_name", self.source);
        for child in children(node) {
            if Some(text(child, self.source)) == module {
                continue;
            }
            let (name, alias) = if child.kind() == "aliased_import" {
                let Some(name) = field_text(child, "name", self.source) else {
                    continue;
                };
                (
                    name,
                    field_text(child, "alias", self.source).unwrap_or(name),
                )
            } else if matches!(child.kind(), "dotted_name" | "identifier") {
                let name = text(child, self.source);
                (name, name.split('.').next().unwrap_or(name))
            } else {
                self.gap("Python wildcard or relative import is unresolved");
                continue;
            };
            let imported = module.unwrap_or(name);
            let canonical = module.map(|m| format!("{m}.{name}")).unwrap_or_else(|| {
                if child.kind() == "aliased_import" {
                    name.into()
                } else {
                    name.split('.').next().unwrap_or(name).into()
                }
            });
            let approved = matches!(
                imported,
                "json"
                    | "math"
                    | "statistics"
                    | "re"
                    | "time"
                    | "pathlib"
                    | "os"
                    | "os.path"
                    | "sys"
                    | "subprocess"
                    | "collections"
                    | "hashlib"
                    | "itertools"
                    | "shutil"
                    | "tomllib"
            );
            if !self.result.imports.contains(&imported.into()) {
                self.result.imports.push(imported.into());
            }
            env.insert(
                alias.into(),
                if approved {
                    if matches!(
                        canonical.as_str(),
                        "subprocess.PIPE" | "subprocess.DEVNULL" | "subprocess.STDOUT"
                    ) {
                        Value::Stream
                    } else if matches!(
                        canonical.as_str(),
                        "math.pi" | "math.e" | "math.tau" | "math.inf" | "math.nan"
                    ) {
                        Value::Data(None)
                    } else {
                        Value::Module(canonical)
                    }
                } else {
                    self.gap(format!(
                        "Python import {imported} is outside the supported standard-library model"
                    ))
                },
            );
        }
    }
    fn expression(&mut self, node: Node<'a>, env: &mut Env) -> Value {
        if !self.tick() {
            return Value::Unknown;
        }
        if let Some(value) = string_literal(node, self.source) {
            return Value::Data(Some(value));
        }
        match node.kind() {
            "true" => Value::Boolean(true),
            "false" => Value::Boolean(false),
            "integer" | "float" | "none" => Value::Data(None),
            "identifier" => env
                .get(text(node, self.source))
                .cloned()
                .unwrap_or_else(|| {
                    self.gap(format!(
                        "Python value {} is unresolved",
                        text(node, self.source)
                    ))
                }),
            "list" | "tuple" | "set" | "expression_list" => Value::Sequence(
                children(node)
                    .into_iter()
                    .map(|n| self.expression(n, env))
                    .collect(),
            ),
            "dictionary" | "pair" => {
                let values: Vec<_> = children(node)
                    .into_iter()
                    .map(|n| self.expression(n, env))
                    .collect();
                if values.iter().all(Value::data) {
                    Value::Data(None)
                } else {
                    self.gap("Python container includes unresolved values")
                }
            }
            "string" => {
                let mut valid = true;
                for child in children(node)
                    .into_iter()
                    .filter(|n| n.kind() == "interpolation")
                {
                    for item in children(child) {
                        if matches!(item.kind(), "type_conversion" | "format_specifier") {
                            if item.kind() == "format_specifier" && !children(item).is_empty() {
                                valid = false;
                            }
                            continue;
                        }
                        valid &= self.expression(item, env).data();
                    }
                }
                if valid {
                    Value::Data(None)
                } else {
                    self.gap("Python formatted string may invoke user code")
                }
            }
            "parenthesized_expression" => children(node)
                .first()
                .map(|n| self.expression(*n, env))
                .unwrap_or(Value::Data(None)),
            "binary_operator" => {
                let (Some(a), Some(b)) = (
                    node.child_by_field_name("left"),
                    node.child_by_field_name("right"),
                ) else {
                    return self.gap("Python binary operation is unresolved");
                };
                let a = self.expression(a, env);
                let b = self.expression(b, env);
                match (field_text(node, "operator", self.source), &a, &b) {
                    (Some("+"), Value::Data(Some(a)), Value::Data(Some(b)))
                        if a.len() + b.len() <= 4096 =>
                    {
                        Value::Data(Some(format!("{a}{b}")))
                    }
                    (Some("/"), Value::Path(Some(a)), Value::Data(Some(b))) => Value::Path(Some(
                        std::path::Path::new(a)
                            .join(b)
                            .to_string_lossy()
                            .into_owned(),
                    )),
                    _ if a.data() && b.data() => Value::Data(None),
                    _ => self.gap("Python operator may invoke user code"),
                }
            }
            "comparison_operator" | "boolean_operator" | "not_operator" | "unary_operator" => {
                let values: Vec<_> = children(node)
                    .into_iter()
                    .map(|n| self.expression(n, env))
                    .collect();
                if values.iter().all(Value::data) {
                    Value::Data(None)
                } else {
                    self.gap("Python comparison or boolean operation may invoke user code")
                }
            }
            "subscript" => {
                let values: Vec<_> = children(node)
                    .into_iter()
                    .map(|n| self.expression(n, env))
                    .collect();
                if values.iter().all(Value::data) {
                    Value::Data(None)
                } else {
                    self.gap("Python subscript may invoke user code")
                }
            }
            "attribute" => {
                let (Some(object), Some(name)) = (
                    node.child_by_field_name("object"),
                    field_text(node, "attribute", self.source),
                ) else {
                    return Value::Unknown;
                };
                match self.expression(object, env) {
                    Value::Module(module) if !name.starts_with('_') => {
                        if matches!(
                            (module.as_str(), name),
                            ("subprocess", "PIPE" | "DEVNULL" | "STDOUT")
                                | ("math", "pi" | "e" | "tau" | "inf" | "nan")
                        ) {
                            if module == "subprocess" {
                                Value::Stream
                            } else {
                                Value::Data(None)
                            }
                        } else {
                            Value::Module(format!("{module}.{name}"))
                        }
                    }
                    Value::Path(path) => match name {
                        "parent" => Value::Path(path.and_then(|p| {
                            std::path::Path::new(&p)
                                .parent()
                                .map(|p| p.to_string_lossy().into_owned())
                        })),
                        "name" | "stem" | "suffix" | "parts" => Value::Data(None),
                        _ => self.gap("Python path attribute is unresolved"),
                    },
                    Value::Process
                        if matches!(name, "stdout" | "stderr" | "returncode" | "args") =>
                    {
                        Value::Data(None)
                    }
                    _ => self.gap("Python attribute may invoke user code"),
                }
            }
            "call" => self.call(node, env),
            "list_comprehension"
            | "set_comprehension"
            | "dictionary_comprehension"
            | "generator_expression" => {
                let mut local = env.clone();
                for clause in children(node)
                    .into_iter()
                    .filter(|n| n.kind() == "for_in_clause")
                {
                    if let (Some(left), Some(right)) = (
                        clause.child_by_field_name("left"),
                        clause.child_by_field_name("right"),
                    ) {
                        let iterable = self.expression(right, &mut local);
                        if !iterable.data() {
                            self.gap("Python comprehension iterator is unresolved");
                        }
                        self.bind(left, Value::Data(None), &mut local);
                    }
                }
                for clause in children(node)
                    .into_iter()
                    .filter(|n| n.kind() != "for_in_clause")
                {
                    let value = if clause.kind() == "if_clause" {
                        children(clause)
                            .first()
                            .map(|n| self.expression(*n, &mut local))
                            .unwrap_or(Value::Unknown)
                    } else {
                        self.expression(clause, &mut local)
                    };
                    if !value.data() {
                        self.gap("Python comprehension value is unresolved");
                    }
                }
                Value::Data(None)
            }
            _ => self.gap(format!("Python {} expression is unsupported", node.kind())),
        }
    }
    fn call(&mut self, node: Node<'a>, env: &mut Env) -> Value {
        let Some(function) = node.child_by_field_name("function") else {
            return Value::Unknown;
        };
        let args = node
            .child_by_field_name("arguments")
            .map(children)
            .unwrap_or_default();
        let mut values = vec![];
        let mut keywords = HashMap::new();
        // Resolve function before evaluating arguments, as Python does.
        let (name, receiver) =
            if function.kind() == "identifier" && !env.contains_key(text(function, self.source)) {
                (text(function, self.source).to_owned(), None)
            } else if function.kind() == "attribute" {
                let object = function
                    .child_by_field_name("object")
                    .map(|n| self.expression(n, env))
                    .unwrap_or(Value::Unknown);
                let name = field_text(function, "attribute", self.source).unwrap_or_default();
                match object {
                    Value::Module(m) => (format!("{m}.{name}"), None),
                    v => (name.to_owned(), Some(v)),
                }
            } else {
                match self.expression(function, env) {
                    Value::Module(name) => (name, None),
                    Value::Function(index) => (format!("@function:{index}"), None),
                    _ => ("@unresolved".into(), None),
                }
            };
        for arg in args {
            if arg.kind() == "keyword_argument" {
                if let (Some(name), Some(value)) = (
                    field_text(arg, "name", self.source),
                    arg.child_by_field_name("value"),
                ) {
                    let value = self.expression(value, env);
                    keywords.insert(name.to_owned(), value);
                }
            } else {
                values.push(self.expression(arg, env));
            }
        }
        let all_data = values.iter().chain(keywords.values()).all(Value::data);
        if let Some(index) = name
            .strip_prefix("@function:")
            .and_then(|s| s.parse::<usize>().ok())
        {
            let f = self.functions[index];
            let params = f
                .child_by_field_name("parameters")
                .map(children)
                .unwrap_or_default();
            if params.len() != values.len() || !keywords.is_empty() {
                return self.gap("Python function argument binding is unresolved");
            }
            let mut local = env.clone();
            // Python locals shadow builtins throughout the function, before assignment.
            if let Some(body) = f.child_by_field_name("body") {
                let mut pending = vec![body];
                while let Some(n) = pending.pop() {
                    if n.kind() == "assignment"
                        && let Some(left) = n.child_by_field_name("left")
                    {
                        self.bind(left, Value::Unknown, &mut local);
                    }
                    pending.extend(children(n));
                }
                for (param, value) in params.into_iter().zip(values) {
                    self.bind(param, value, &mut local);
                }
                self.depth += 1;
                let value = self
                    .statement(body, &mut local)
                    .unwrap_or(Value::Data(None));
                self.depth -= 1;
                // Function parameters can alias caller-owned mutable containers.
                // Do not reuse a literal argv after a possible mutation.
                for value in env.values_mut() {
                    if matches!(value, Value::Sequence(_)) {
                        *value = Value::Data(None);
                    }
                }
                return value;
            }
        }
        if let Some(receiver) = receiver {
            if matches!(
                name.as_str(),
                "append" | "extend" | "insert" | "pop" | "sort" | "update" | "setdefault"
            ) {
                for value in env.values_mut() {
                    if matches!(value, Value::Sequence(_)) {
                        *value = Value::Data(None);
                    }
                }
            }
            return self.method(node, &name, receiver, &values, &keywords, all_data);
        }
        if name == "print"
            && values.iter().all(Value::data)
            && keywords.iter().all(|(key, value)| match key.as_str() {
                "file" => matches!(value, Value::File(_, _)),
                "sep" | "end" | "flush" => value.data(),
                _ => false,
            })
        {
            return Value::Data(None);
        }
        if matches!(name.as_str(), "json.load" | "json.dump" | "tomllib.load") {
            let handle = if name == "json.dump" {
                values.get(1)
            } else {
                values.first()
            };
            if matches!(handle, Some(Value::File(_, _)))
                && (name != "json.dump" || values.first().is_some_and(Value::data))
                && keywords.iter().all(|(key, value)| {
                    value.data()
                        && matches!(
                            key.as_str(),
                            "indent"
                                | "sort_keys"
                                | "ensure_ascii"
                                | "allow_nan"
                                | "skipkeys"
                                | "check_circular"
                                | "strict"
                        )
                })
            {
                return Value::Data(None);
            }
        }
        if name == "pathlib.Path" && values.len() == 1 && keywords.is_empty() {
            return Value::Path(values[0].string());
        }
        if name == "open" {
            let path = keywords
                .get("file")
                .or_else(|| values.first())
                .and_then(Value::string);
            let mode = keywords.get("mode").or_else(|| values.get(1));
            let mode = match mode {
                None => Some("r".into()),
                Some(value) => value.string(),
            };
            if !all_data
                || keywords.keys().any(|k| {
                    !matches!(
                        k.as_str(),
                        "file"
                            | "mode"
                            | "encoding"
                            | "errors"
                            | "newline"
                            | "buffering"
                            | "closefd"
                    )
                })
                || mode.is_none()
            {
                return self.gap("Python open mode, opener, or arguments are unresolved");
            }
            let mode = mode.unwrap();
            let write = mode.contains(['w', 'a', 'x', '+']);
            self.effect(
                node,
                if write {
                    EffectKind::FileWrite
                } else {
                    EffectKind::FileRead
                },
                "open",
                path.clone(),
                false,
                mode.contains('a'),
            );
            if mode.contains('+') {
                self.effect(
                    node,
                    EffectKind::FileRead,
                    "open",
                    path.clone(),
                    false,
                    false,
                );
            }
            return Value::File(path, mode);
        }
        if matches!(
            name.as_str(),
            "os.remove" | "os.unlink" | "shutil.rmtree" | "os.mkdir" | "os.makedirs"
        ) && all_data
        {
            if values.len() > 2
                || keywords.keys().any(|key| {
                    !matches!(key.as_str(), "path" | "mode" | "exist_ok" | "ignore_errors")
                })
            {
                return self.gap("Python filesystem descriptor, callback, or option is unresolved");
            }
            let path = values
                .first()
                .or_else(|| keywords.get("path"))
                .and_then(Value::string);
            self.effect(
                node,
                if name == "os.mkdir" || name == "os.makedirs" {
                    EffectKind::FileWrite
                } else {
                    EffectKind::FileDelete
                },
                &name,
                path,
                name == "shutil.rmtree",
                false,
            );
            return Value::Data(None);
        }
        if name.starts_with("subprocess.")
            && matches!(
                name.rsplit('.').next(),
                Some("run" | "call" | "check_call" | "check_output")
            )
        {
            let allowed = keywords.keys().all(|k| {
                matches!(
                    k.as_str(),
                    "check"
                        | "capture_output"
                        | "text"
                        | "encoding"
                        | "errors"
                        | "timeout"
                        | "shell"
                        | "stdout"
                        | "stderr"
                )
            });
            let shell = match keywords.get("shell") {
                None => Some(false),
                Some(Value::Boolean(value)) => Some(*value),
                _ => None,
            };
            let command = values.first();
            if keywords.iter().any(|(key, value)| {
                matches!(key.as_str(), "stdout" | "stderr")
                    && !matches!(value, Value::Stream | Value::File(_, _))
            }) {
                return self.gap("Python subprocess output file descriptor is unresolved");
            }
            let supported_values = keywords.iter().all(|(key, value)| {
                value.data()
                    || matches!(key.as_str(), "stdout" | "stderr")
                        && matches!(value, Value::File(_, _))
            });
            if allowed
                && values.len() == 1
                && shell == Some(false)
                && supported_values
                && let Some(Value::Sequence(argv)) = command
            {
                let argv: Option<Vec<_>> = argv.iter().map(Value::string).collect();
                if let Some(argv) = argv
                    && !argv.is_empty()
                {
                    self.result.commands.push(Command { argv, shell: false });
                    return Value::Process;
                }
            }
            if allowed
                && shell == Some(true)
                && supported_values
                && values.len() == 1
                && let Some(command) = command.and_then(Value::string)
            {
                self.result.commands.push(Command {
                    argv: vec![command],
                    shell: true,
                });
                return Value::Process;
            }
            return self
                .gap("Python subprocess argv, shell mode, or execution overrides are unresolved");
        }
        let pure = matches!(
            name.as_str(),
            "print"
                | "len"
                | "str"
                | "int"
                | "float"
                | "bool"
                | "abs"
                | "round"
                | "min"
                | "max"
                | "sum"
                | "all"
                | "any"
                | "sorted"
                | "list"
                | "tuple"
                | "dict"
                | "set"
                | "frozenset"
                | "range"
                | "enumerate"
                | "zip"
                | "reversed"
                | "repr"
                | "ord"
                | "chr"
                | "hex"
                | "bin"
                | "oct"
                | "AssertionError"
                | "ValueError"
                | "RuntimeError"
                | "TypeError"
                | "SystemExit"
                | "json.loads"
                | "json.dumps"
                | "tomllib.loads"
                | "math.sqrt"
                | "math.floor"
                | "math.ceil"
                | "math.isclose"
                | "math.isfinite"
                | "math.isnan"
                | "math.log"
                | "math.log10"
                | "math.exp"
                | "math.sin"
                | "math.cos"
                | "math.fsum"
                | "math.prod"
                | "statistics.mean"
                | "statistics.median"
                | "statistics.stdev"
                | "statistics.pstdev"
                | "re.search"
                | "re.match"
                | "re.fullmatch"
                | "re.findall"
                | "re.split"
                | "re.escape"
                | "time.time"
                | "time.perf_counter"
                | "time.monotonic"
                | "time.sleep"
                | "os.path.join"
                | "os.path.basename"
                | "os.path.dirname"
                | "os.path.splitext"
                | "os.path.normpath"
                | "collections.Counter"
        );
        if pure
            && all_data
            && !keywords.contains_key("file")
            && !keywords.contains_key("key")
            && !keywords.contains_key("default")
            && !keywords.contains_key("object_hook")
            && !keywords.contains_key("object_pairs_hook")
            && !keywords.contains_key("parse_int")
            && !keywords.contains_key("parse_float")
            && !keywords.contains_key("parse_constant")
            && !keywords.contains_key("cls")
        {
            return Value::Data(None);
        }
        self.gap(format!(
            "Python call {name} is unresolved or has unsupported argument provenance"
        ))
    }
    fn method(
        &mut self,
        node: Node<'a>,
        name: &str,
        receiver: Value,
        args: &[Value],
        keywords: &HashMap<String, Value>,
        all_data: bool,
    ) -> Value {
        match receiver {
            Value::Path(path) if all_data => {
                let kind = match name {
                    "read_text" | "read_bytes" | "exists" | "is_file" | "is_dir" | "stat" => {
                        Some(EffectKind::FileRead)
                    }
                    "write_text" | "write_bytes" | "touch" | "mkdir" => Some(EffectKind::FileWrite),
                    "unlink" | "rmdir" => Some(EffectKind::FileDelete),
                    _ => None,
                };
                if let Some(kind) = kind {
                    self.effect(
                        node,
                        kind,
                        &format!("pathlib.Path.{name}"),
                        path,
                        false,
                        false,
                    );
                    return Value::Data(None);
                }
                if name == "joinpath" && keywords.is_empty() {
                    let joined = args
                        .iter()
                        .try_fold(path, |base, arg| {
                            Some(Some(
                                std::path::Path::new(&base?)
                                    .join(arg.string()?)
                                    .to_string_lossy()
                                    .into_owned(),
                            ))
                        })
                        .flatten();
                    return Value::Path(joined);
                }
            }
            Value::File(path, mode) if all_data => {
                if matches!(
                    name,
                    "read" | "readline" | "readlines" | "close" | "flush" | "write" | "writelines"
                ) {
                    if matches!(name, "write" | "writelines")
                        && !mode.contains(['w', 'a', 'x', '+'])
                    {
                        return self.gap("Python file write mode is unresolved");
                    }
                    if matches!(name, "write" | "writelines") {
                        self.effect(
                            node,
                            EffectKind::FileWrite,
                            "file.write",
                            path,
                            false,
                            mode.contains('a'),
                        );
                    }
                    return Value::Data(None);
                }
            }
            v if v.data()
                && all_data
                && matches!(
                    name,
                    "get"
                        | "keys"
                        | "values"
                        | "items"
                        | "split"
                        | "splitlines"
                        | "strip"
                        | "lstrip"
                        | "rstrip"
                        | "replace"
                        | "startswith"
                        | "endswith"
                        | "lower"
                        | "upper"
                        | "casefold"
                        | "count"
                        | "index"
                        | "find"
                        | "join"
                        | "encode"
                        | "decode"
                        | "append"
                        | "extend"
                        | "insert"
                        | "pop"
                        | "copy"
                        | "sort"
                        | "update"
                        | "setdefault"
                )
                && !keywords.contains_key("key") =>
            {
                return Value::Data(None);
            }
            _ => {}
        }
        self.gap(format!(
            "Python method {name} is unresolved or may invoke user code"
        ))
    }
}
