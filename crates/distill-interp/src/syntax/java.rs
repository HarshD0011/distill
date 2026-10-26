//! Conditional Java source observations. No print-only or complete-program proof.
use super::{
    children, field_text,
    flow::{Environment, Value},
    operations::Observation,
};
use distill_core::EffectKind;
use tree_sitter::Node;

pub(super) fn collect(root: Node<'_>, source: &str) -> Vec<Observation> {
    let mut out = Vec::new();
    visit(root, source, &mut Environment::default(), &mut out);
    out
}

fn path(node: Node<'_>, source: &str, env: &Environment) -> Option<String> {
    if let Some(value) = env.string(node, source) {
        return Some(value);
    }
    if node.kind() == "method_invocation" {
        let object = field_text(node, "object", source)?;
        let name = field_text(node, "name", source)?;
        if matches!(
            (object, name),
            ("Path" | "java.nio.file.Path", "of") | ("Paths" | "java.nio.file.Paths", "get")
        ) {
            let args = children(node.child_by_field_name("arguments")?);
            if args.len() == 1 {
                return env.string(args[0], source);
            }
        }
    }
    None
}

fn visit(node: Node<'_>, source: &str, env: &mut Environment, out: &mut Vec<Observation>) {
    let kind = node.kind();
    if matches!(
        kind,
        "if_statement"
            | "for_statement"
            | "enhanced_for_statement"
            | "while_statement"
            | "do_statement"
            | "try_statement"
            | "switch_expression"
            | "ternary_expression"
            | "method_declaration"
            | "constructor_declaration"
            | "lambda_expression"
    ) {
        for child in children(node) {
            visit(child, source, &mut Environment::default(), out);
        }
        env.invalidate();
        return;
    }
    if kind == "variable_declarator" {
        let value = node
            .child_by_field_name("value")
            .and_then(|n| path(n, source, env));
        for child in children(node) {
            visit(child, source, env, out);
        }
        if let Some(name) = field_text(node, "name", source) {
            env.set(name, value.map_or(Value::Unknown, Value::String));
        }
        return;
    }
    if kind == "assignment_expression" || kind == "update_expression" {
        for child in children(node) {
            visit(child, source, env, out);
        }
        env.invalidate();
        return;
    }
    if kind != "method_invocation" && kind != "object_creation_expression" {
        for child in children(node) {
            visit(child, source, env, out);
        }
        return;
    }
    let name = field_text(node, "name", source)
        .or_else(|| field_text(node, "type", source))
        .unwrap_or("");
    let object = field_text(node, "object", source).unwrap_or("");
    let call = if object.is_empty() {
        name.to_owned()
    } else {
        format!("{object}.{name}")
    };
    let args = node
        .child_by_field_name("arguments")
        .map(children)
        .unwrap_or_default();
    if let Some(object) = node.child_by_field_name("object") {
        visit(object, source, env, out);
    }
    let mut values = Vec::new();
    for arg in &args {
        values.push(path(*arg, source, env));
        visit(*arg, source, env, out);
    }
    let files = matches!(object, "Files" | "java.nio.file.Files");
    let operation = if files {
        match name {
            "delete" | "deleteIfExists" => Some((EffectKind::FileDelete, 0)),
            "write" | "writeString" | "newOutputStream" | "newBufferedWriter" | "createFile"
            | "createDirectory" | "createDirectories" => Some((EffectKind::FileWrite, 0)),
            "readAllBytes" | "readString" | "readAllLines" | "newInputStream"
            | "newBufferedReader" => Some((EffectKind::FileRead, 0)),
            "copy" | "move" => Some((EffectKind::FileWrite, 1)),
            _ => None,
        }
    } else if matches!(
        name,
        "FileOutputStream" | "FileWriter" | "java.io.FileOutputStream" | "java.io.FileWriter"
    ) {
        Some((EffectKind::FileWrite, 0))
    } else if matches!(
        name,
        "FileInputStream" | "FileReader" | "java.io.FileInputStream" | "java.io.FileReader"
    ) {
        Some((EffectKind::FileRead, 0))
    } else if (name == "exec" && object.contains("getRuntime()"))
        || (name == "start" && object.contains("ProcessBuilder"))
        || (matches!(object, "System" | "java.lang.System")
            && matches!(name, "load" | "loadLibrary"))
    {
        Some((EffectKind::Execute, 0))
    } else {
        None
    };
    if let Some((kind, index)) = operation {
        out.push(Observation {
            kind,
            call: call.clone(),
            path: if kind == EffectKind::Execute {
                None
            } else {
                values.get(index).cloned().flatten()
            },
            recursive: false,
            append: false,
            line: node.start_position().row + 1,
            column: node.start_position().column + 1,
        });
        if files && matches!(name, "copy" | "move") {
            out.push(Observation {
                kind: if name == "move" {
                    EffectKind::FileDelete
                } else {
                    EffectKind::FileRead
                },
                call,
                path: values.first().cloned().flatten(),
                recursive: false,
                append: false,
                line: node.start_position().row + 1,
                column: node.start_position().column + 1,
            });
        }
    }
    if operation.is_none() && !matches!(name, "of" | "get" | "println" | "print") {
        env.invalidate();
    }
}
