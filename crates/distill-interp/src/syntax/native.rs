use tree_sitter::Node;

use super::{Language, children, field_text, literal, text};

pub(super) fn print_only(language: Language, root: Node<'_>, source: &str) -> bool {
    match language {
        Language::Go => go(root, source),
        Language::Rust => rust(root, source),
        Language::C | Language::Cpp => c_family(language, root, source),
        _ => false,
    }
}

fn go(root: Node<'_>, source: &str) -> bool {
    let items = children(root);
    if items.len() != 3
        || items[0].kind() != "package_clause"
        || children(items[0]).len() != 1
        || text(children(items[0])[0], source) != "main"
        || items[1].kind() != "import_declaration"
        || items[2].kind() != "function_declaration"
    {
        return false;
    }
    let mut imports = children(items[1]);
    if imports.len() == 1 && imports[0].kind() == "import_spec_list" {
        imports = children(imports[0]);
    }
    if imports.len() != 1
        || imports[0].kind() != "import_spec"
        || children(imports[0]).len() != 1
        || field_text(imports[0], "path", source) != Some("\"fmt\"")
    {
        return false;
    }
    let function = items[2];
    if field_text(function, "name", source) != Some("main")
        || children(function).len() != 3
        || !function
            .child_by_field_name("parameters")
            .is_some_and(|params| children(params).is_empty())
    {
        return false;
    }
    let Some(body) = function.child_by_field_name("body") else {
        return false;
    };
    let parts = children(body);
    if parts.len() != 1 || parts[0].kind() != "statement_list" {
        return false;
    }
    let statements = children(parts[0]);
    !statements.is_empty()
        && statements.into_iter().all(|statement| {
            let expressions = children(statement);
            if statement.kind() != "expression_statement" || expressions.len() != 1 {
                return false;
            }
            let call = expressions[0];
            let Some(function) = call.child_by_field_name("function") else {
                return false;
            };
            call.kind() == "call_expression"
                && function.kind() == "selector_expression"
                && field_text(function, "operand", source) == Some("fmt")
                && matches!(
                    field_text(function, "field", source),
                    Some("Print" | "Println" | "Printf")
                )
                && call
                    .child_by_field_name("arguments")
                    .is_some_and(|args| children(args).into_iter().all(|arg| literal(arg, source)))
        })
}

fn rust(root: Node<'_>, source: &str) -> bool {
    let items = children(root);
    if items.len() != 1 || items[0].kind() != "function_item" {
        return false;
    }
    let function = items[0];
    if field_text(function, "name", source) != Some("main")
        || children(function).len() != 3
        || !function
            .child_by_field_name("parameters")
            .is_some_and(|params| children(params).is_empty())
    {
        return false;
    }
    let Some(body) = function.child_by_field_name("body") else {
        return false;
    };
    let statements = children(body);
    !statements.is_empty()
        && statements.into_iter().all(|statement| {
            let parts = children(statement);
            let call = if statement.kind() == "expression_statement" && parts.len() == 1 {
                parts[0]
            } else {
                statement
            };
            if call.kind() != "macro_invocation"
                || !matches!(
                    field_text(call, "macro", source),
                    Some("print" | "println" | "eprint" | "eprintln")
                )
            {
                return false;
            }
            let parts = children(call);
            if parts.len() != 2 || parts[1].kind() != "token_tree" {
                return false;
            }
            let args = children(parts[1]);
            if args.is_empty() || args[0].kind() != "string_literal" {
                return false;
            }
            // Format capture can refer to identifiers not represented as AST arguments.
            if text(args[0], source).contains('{') {
                return false;
            }
            // Tokens inside macros are not parsed as expressions. Validate punctuation
            // too, so literal tokens separated by an operator cannot hide extra syntax.
            let mut cursor = parts[1].walk();
            parts[1].children(&mut cursor).all(|node| {
                matches!(
                    node.kind(),
                    "(" | ")" | "," | "comment" | "line_comment" | "block_comment"
                ) || literal(node, source)
            })
        })
}

fn c_family(language: Language, root: Node<'_>, source: &str) -> bool {
    // Older C/C++ standards translate trigraphs before lexical analysis. Do not
    // trust a source tree when the compiler may see different tokens or escapes.
    if source
        .as_bytes()
        .windows(3)
        .any(|bytes| bytes[0..2] == *b"??" && b"=/'()!<>-".contains(&bytes[2]))
    {
        return false;
    }
    let mut function = None;
    let mut includes = 0;
    for item in children(root) {
        match item.kind() {
            "preproc_include" if children(item).len() == 1 => {
                let expected = if matches!(language, Language::C) {
                    "<stdio.h>"
                } else {
                    "<iostream>"
                };
                if field_text(item, "path", source) != Some(expected) {
                    return false;
                }
                includes += 1;
            }
            "function_definition" if function.is_none() => function = Some(item),
            _ => return false,
        }
    }
    let Some(function) = function else {
        return false;
    };
    if includes != 1
        || field_text(function, "type", source) != Some("int")
        || children(function).len() != 3
    {
        return false;
    }
    let Some(declaration) = function.child_by_field_name("declarator") else {
        return false;
    };
    if declaration.kind() != "function_declarator"
        || children(declaration).len() != 2
        || field_text(declaration, "declarator", source) != Some("main")
    {
        return false;
    }
    let Some(params) = declaration.child_by_field_name("parameters") else {
        return false;
    };
    if !children(params).is_empty()
        && text(params, source).split_whitespace().collect::<String>() != "(void)"
    {
        return false;
    }
    let Some(body) = function.child_by_field_name("body") else {
        return false;
    };
    let mut printed = false;
    for statement in children(body) {
        let parts = children(statement);
        if statement.kind() == "return_statement"
            && parts.len() == 1
            && text(parts[0], source) == "0"
        {
            continue;
        }
        if statement.kind() != "expression_statement" || parts.len() != 1 {
            return false;
        }
        if matches!(language, Language::Cpp) {
            if !cout(parts[0], source) {
                return false;
            }
        } else if !c_print(parts[0], source) {
            return false;
        }
        printed = true;
    }
    printed
}

fn qualified(node: Node<'_>, namespace: &str, name: &str, source: &str) -> bool {
    node.kind() == "qualified_identifier"
        && field_text(node, "scope", source) == Some(namespace)
        && field_text(node, "name", source) == Some(name)
        && children(node).len() == 2
}

fn cout(node: Node<'_>, source: &str) -> bool {
    if node.kind() != "binary_expression" || field_text(node, "operator", source) != Some("<<") {
        return false;
    }
    let (Some(left), Some(right)) = (
        node.child_by_field_name("left"),
        node.child_by_field_name("right"),
    ) else {
        return false;
    };
    (qualified(left, "std", "cout", source) || cout(left, source))
        && (literal(right, source) || qualified(right, "std", "endl", source))
}

fn c_print(node: Node<'_>, source: &str) -> bool {
    if node.kind() != "call_expression"
        || !matches!(
            field_text(node, "function", source),
            Some("puts" | "printf")
        )
    {
        return false;
    }
    let Some(args) = node.child_by_field_name("arguments") else {
        return false;
    };
    let args = children(args);
    if args.len() != 1 || args[0].kind() != "string_literal" {
        return false;
    }
    // C printf accepts %n, arbitrary pointers and missing varargs. Only accept
    // a literal without conversions; puts has no formatting semantics.
    if field_text(node, "function", source) == Some("printf") {
        let value = text(args[0], source);
        // Hex, octal and Unicode escapes can encode a percent sign. Accept
        // ordinary escapes only, and leave encoded format strings unresolved.
        let mut chars = value.chars();
        while let Some(ch) = chars.next() {
            if ch == '\\'
                && !chars.next().is_some_and(|ch| {
                    matches!(
                        ch,
                        'n' | 't' | 'r' | 'a' | 'b' | 'f' | 'v' | '\\' | '\'' | '"' | '?'
                    )
                })
            {
                return false;
            }
        }
        if value.replace("%%", "").contains('%') {
            return false;
        }
    }
    true
}
