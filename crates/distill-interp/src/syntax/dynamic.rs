use std::collections::HashSet;

use tree_sitter::Node;

use super::{Language, children, field_text, pure, text};

pub(super) fn print_only(language: Language, root: Node<'_>, source: &str) -> bool {
    let mut symbols = HashSet::new();
    let mut printed = false;
    let mut asserted = false;
    for statement in children(root) {
        match (language, statement.kind()) {
            (Language::Python, "expression_statement") => {
                let parts = children(statement);
                if parts.len() != 1 {
                    return false;
                }
                let expr = parts[0];
                if expr.kind() == "assignment" {
                    if !binding(expr, "left", "right", source, &mut symbols) {
                        return false;
                    }
                } else if python_print(expr, source, &symbols) {
                    printed = true;
                } else {
                    return false;
                }
            }
            (Language::Python, "assert_statement") => {
                let values = children(statement);
                if values.is_empty() || !values.iter().all(|value| pure(*value, source, &symbols)) {
                    return false;
                }
                asserted = true;
            }
            (
                Language::JavaScript | Language::TypeScript,
                "lexical_declaration" | "variable_declaration",
            ) => {
                for declaration in children(statement) {
                    if declaration.kind() != "variable_declarator"
                        || !binding(declaration, "name", "value", source, &mut symbols)
                    {
                        return false;
                    }
                }
            }
            (Language::JavaScript | Language::TypeScript, "expression_statement") => {
                let parts = children(statement);
                if parts.len() != 1 || !js_print(parts[0], source, &symbols) {
                    return false;
                }
                printed = true;
            }
            // Empty statements do not hide other statements; all siblings are checked.
            (Language::JavaScript | Language::TypeScript, "empty_statement") => {}
            _ => return false,
        }
    }
    printed || asserted
}

fn binding(
    node: Node<'_>,
    name: &str,
    value: &str,
    source: &str,
    symbols: &mut HashSet<String>,
) -> bool {
    let (Some(name), Some(value)) = (
        node.child_by_field_name(name),
        node.child_by_field_name(value),
    ) else {
        return false;
    };
    if name.kind() != "identifier" || children(node).len() != 2 {
        return false;
    }
    let name = text(name, source);
    if matches!(
        name,
        "print" | "console" | "require" | "process" | "globalThis" | "__builtins__"
    ) || !pure(value, source, symbols)
    {
        return false;
    }
    symbols.insert(name.to_owned());
    true
}

fn python_print(node: Node<'_>, source: &str, symbols: &HashSet<String>) -> bool {
    if node.kind() != "call" || field_text(node, "function", source) != Some("print") {
        return false;
    }
    let Some(args) = node.child_by_field_name("arguments") else {
        return false;
    };
    let mut keywords = HashSet::new();
    children(args).into_iter().all(|arg| {
        if arg.kind() == "keyword_argument" {
            let Some(name) = field_text(arg, "name", source) else {
                return false;
            };
            if !keywords.insert(name) || !matches!(name, "sep" | "end" | "flush") {
                return false;
            }
            arg.child_by_field_name("value")
                .is_some_and(|value| pure(value, source, symbols))
        } else {
            pure(arg, source, symbols)
        }
    })
}

fn js_print(node: Node<'_>, source: &str, symbols: &HashSet<String>) -> bool {
    if node.kind() != "call_expression" {
        return false;
    }
    let Some(function) = node.child_by_field_name("function") else {
        return false;
    };
    if function.kind() != "member_expression"
        || field_text(function, "object", source) != Some("console")
        || field_text(function, "property", source) != Some("log")
        || children(function).len() != 2
    {
        return false;
    }
    node.child_by_field_name("arguments").is_some_and(|args| {
        children(args)
            .into_iter()
            .all(|arg| pure(arg, source, symbols))
    })
}
