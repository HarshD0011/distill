//! Import bindings supply conditional observations, never a safety proof.
use super::flow::{Environment, Value, simple_string};
use super::{children, field_text, text};
use tree_sitter::Node;

pub(crate) struct Import {
    pub specifier: Option<String>,
}

pub(super) fn imports(root: Node<'_>, source: &str) -> Vec<Import> {
    let mut pending = vec![root];
    let mut result = vec![];
    while let Some(node) = pending.pop() {
        let value = if matches!(node.kind(), "import_statement" | "export_statement") {
            node.child_by_field_name("source")
        } else if node.kind() == "call_expression"
            && node
                .child_by_field_name("function")
                .is_some_and(|v| v.kind() == "import" || text(v, source) == "require")
        {
            node.child_by_field_name("arguments")
                .and_then(|args| children(args).first().copied())
        } else {
            None
        };
        if let Some(value) = value {
            result.push(Import {
                specifier: simple_string(value, source),
            });
        }
        pending.extend(children(node).into_iter().rev());
    }
    result
}

pub(super) fn builtin(module: &str) -> Option<&'static str> {
    match module.strip_prefix("node:").unwrap_or(module) {
        "fs" | "fs/promises" => Some("fs"),
        "child_process" => Some("child_process"),
        "http" => Some("http"),
        "https" => Some("https"),
        _ => None,
    }
}

pub(super) fn bind_import(node: Node<'_>, source: &str, env: &mut Environment) {
    let module = node
        .child_by_field_name("source")
        .and_then(|v| simple_string(v, source));
    let module = module.as_deref().and_then(builtin);
    for clause in children(node)
        .into_iter()
        .filter(|v| v.kind() == "import_clause")
    {
        for binding in children(clause) {
            match binding.kind() {
                "identifier" => env.set(
                    text(binding, source),
                    module.map_or(Value::Unknown, |v| Value::Callable(v.into())),
                ),
                "namespace_import" => {
                    if let Some(name) = children(binding)
                        .into_iter()
                        .find(|v| v.kind() == "identifier")
                    {
                        env.set(
                            text(name, source),
                            module.map_or(Value::Unknown, |v| Value::Callable(v.into())),
                        );
                    }
                }
                "named_imports" => {
                    for spec in children(binding) {
                        let Some(name) = field_text(spec, "name", source) else {
                            continue;
                        };
                        let alias = field_text(spec, "alias", source).unwrap_or(name);
                        let value = module.map_or(Value::Unknown, |module| {
                            Value::Callable(if module == "fs" && name == "promises" {
                                module.into()
                            } else {
                                format!("{module}.{name}")
                            })
                        });
                        env.set(alias, value);
                    }
                }
                _ => env.invalidate(),
            }
        }
    }
}
