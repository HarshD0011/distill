//! Bounded, ordered local propagation used for conditional effect observations.
//! This does not establish complete program behavior or authorize execution.
use std::collections::HashMap;

use tree_sitter::Node;

use super::{children, field_text, text};

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum Value {
    String(String),
    Callable(String),
    Unknown,
}

#[derive(Clone, Default)]
pub(super) struct Environment(HashMap<String, Value>);

impl Environment {
    pub fn set(&mut self, name: &str, value: Value) {
        self.0.insert(name.to_owned(), value);
    }

    pub fn invalidate(&mut self) {
        // Retain tombstones so a shadowed name never reappears as a builtin.
        for value in self.0.values_mut() {
            *value = Value::Unknown;
        }
    }

    pub fn merge_possible(&mut self, branch: &Self) {
        for (name, value) in &branch.0 {
            if self.0.get(name) != Some(value) {
                self.0.insert(name.clone(), Value::Unknown);
            }
        }
    }

    pub fn function_scope(&self) -> Self {
        Self(
            self.0
                .iter()
                .map(|(name, value)| {
                    (
                        name.clone(),
                        match value {
                            Value::Callable(_) => value.clone(),
                            _ => Value::Unknown,
                        },
                    )
                })
                .collect(),
        )
    }

    pub fn value(&self, node: Node<'_>, source: &str) -> Value {
        if let Some(value) = simple_string(node, source) {
            return Value::String(value);
        }
        match node.kind() {
            "identifier" => self
                .0
                .get(text(node, source))
                .cloned()
                .unwrap_or_else(|| Value::Callable(text(node, source).to_owned())),
            "parenthesized_expression" => {
                let items = children(node);
                if items.len() == 1 {
                    self.value(items[0], source)
                } else {
                    Value::Unknown
                }
            }
            "reference_expression" => node
                .child_by_field_name("value")
                .map(|value| self.value(value, source))
                .unwrap_or(Value::Unknown),
            "binary_operator" | "binary_expression"
                if field_text(node, "operator", source) == Some("+") =>
            {
                let (Some(left), Some(right)) = (
                    node.child_by_field_name("left"),
                    node.child_by_field_name("right"),
                ) else {
                    return Value::Unknown;
                };
                match (self.value(left, source), self.value(right, source)) {
                    (Value::String(left), Value::String(right))
                        if left.len() + right.len() <= 4096 =>
                    {
                        Value::String(left + &right)
                    }
                    _ => Value::Unknown,
                }
            }
            _ => self
                .callee(node, source)
                .map(Value::Callable)
                .unwrap_or(Value::Unknown),
        }
    }

    pub fn string(&self, node: Node<'_>, source: &str) -> Option<String> {
        match self.value(node, source) {
            Value::String(value) => Some(value),
            _ => None,
        }
    }

    pub fn callee(&self, node: Node<'_>, source: &str) -> Option<String> {
        match node.kind() {
            "identifier" | "field_identifier" | "namespace_identifier" | "type_identifier" => {
                let name = text(node, source);
                match self.0.get(name) {
                    Some(Value::Callable(value)) => Some(value.clone()),
                    Some(_) => None,
                    // Unbound spelling supplies a conditional observation only.
                    None => Some(name.to_owned()),
                }
            }
            "attribute" | "member_expression" | "selector_expression" | "field_expression" => {
                let (object, property) = match node.kind() {
                    "attribute" => ("object", "attribute"),
                    "member_expression" => ("object", "property"),
                    "field_expression" => ("value", "field"),
                    _ => ("operand", "field"),
                };
                let object = self.callee(node.child_by_field_name(object)?, source)?;
                Some(format!("{object}.{}", field_text(node, property, source)?))
            }
            "scoped_identifier" | "qualified_identifier" => Some(format!(
                "{}::{}",
                self.callee(
                    node.child_by_field_name("path")
                        .or_else(|| node.child_by_field_name("scope"))?,
                    source
                )?,
                self.callee(node.child_by_field_name("name")?, source)?
            )),
            "call_expression" => {
                let function = self.callee(node.child_by_field_name("function")?, source)?;
                if matches!(
                    function.as_str(),
                    "std::process::Command::new" | "exec.Command"
                ) {
                    return Some("process_builder".into());
                }
                if function != "require" || self.0.contains_key("require") {
                    return None;
                }
                let args = children(node.child_by_field_name("arguments")?);
                if args.len() != 1 {
                    return None;
                }
                let module = self.string(args[0], source)?;
                let module = module.strip_prefix("node:").unwrap_or(&module);
                matches!(module, "fs" | "child_process" | "http" | "https")
                    .then(|| module.to_owned())
            }
            _ => None,
        }
    }
}

pub(super) fn simple_string(node: Node<'_>, source: &str) -> Option<String> {
    if !matches!(
        node.kind(),
        "string" | "string_literal" | "interpreted_string_literal"
    ) {
        return None;
    }
    let value = text(node, source);
    let mark = *value.as_bytes().first()?;
    if !matches!(mark, b'\'' | b'"') || value.as_bytes().last() != Some(&mark) || value.len() < 2 {
        return None;
    }
    let value = &value[1..value.len() - 1];
    // Escapes, prefixes, triple quotes and interpolation remain unresolved.
    if value.len() > 4096
        || value.contains(['\\', '\'', '"', '\n'])
        || children(node)
            .iter()
            .any(|child| matches!(child.kind(), "interpolation" | "template_substitution"))
    {
        return None;
    }
    Some(value.to_owned())
}

pub(super) fn binding_name<'a>(node: Node<'_>, source: &'a str) -> Option<&'a str> {
    match node.kind() {
        "identifier" => Some(text(node, source)),
        "pointer_declarator" | "reference_declarator" => {
            binding_name(node.child_by_field_name("declarator")?, source)
        }
        "expression_list" if children(node).len() == 1 => binding_name(children(node)[0], source),
        _ => None,
    }
}
