//! Source effects with ordered local propagation. Observations never authorize code.
use distill_core::EffectKind;
use tree_sitter::Node;

use super::flow::{Environment, Value, binding_name};
use super::{Language, children, field_text, text};

pub(crate) struct Observation {
    pub kind: EffectKind,
    pub call: String,
    pub path: Option<String>,
    pub recursive: bool,
    pub append: bool,
    pub line: usize,
    pub column: usize,
}

pub(super) fn collect(language: Language, root: Node<'_>, source: &str) -> Vec<Observation> {
    if matches!(language, Language::Java) {
        return super::java::collect(root, source);
    }
    let mut result = Vec::new();
    visit(
        language,
        root,
        source,
        &mut Environment::default(),
        &mut result,
    );
    result.sort_by_key(|item| (item.line, item.column));
    result
}

fn visit(
    language: Language,
    node: Node<'_>,
    source: &str,
    env: &mut Environment,
    result: &mut Vec<Observation>,
) {
    let kind = node.kind();
    if matches!(
        kind,
        "if_statement"
            | "for_statement"
            | "for_in_statement"
            | "while_statement"
            | "try_statement"
            | "match_statement"
            | "switch_statement"
            | "conditional_expression"
            | "if_expression"
            | "match_expression"
            | "for_expression"
            | "while_expression"
            | "loop_expression"
            | "expression_switch_statement"
            | "select_statement"
            | "boolean_operator"
            | "boolean_expression"
    ) {
        // Analyze possible branches independently; a branch assignment is never
        // assumed to hold after the join. Unsupported joins keep tombstones.
        let mut base = env.clone();
        if matches!(
            kind,
            "for_statement" | "for_in_statement" | "for_expression"
        ) && let Some(binding) = node
            .child_by_field_name("left")
            .or_else(|| node.child_by_field_name("pattern"))
        {
            invalidate_names(binding, source, &mut base);
        }
        for child in children(node) {
            let mut local = base.clone();
            visit(language, child, source, &mut local, result);
            env.merge_possible(&local);
        }
        return;
    }
    if matches!(
        kind,
        "function_definition"
            | "function_declaration"
            | "function_item"
            | "method_declaration"
            | "arrow_function"
            | "lambda"
    ) {
        let mut local = env.function_scope();
        let parameters = node
            .child_by_field_name("parameters")
            .or_else(|| node.child_by_field_name("parameter"));
        if let Some(parameters) = parameters {
            // Defaults can execute while defining a function. Collect those in
            // the outer environment before installing parameter shadowing.
            visit(language, parameters, source, &mut env.clone(), result);
            parameter_names(parameters, source, &mut local);
        }
        for child in children(node) {
            if Some(child) != parameters {
                visit(language, child, source, &mut local, result);
            }
        }
        if let Some(name) = field_text(node, "name", source) {
            env.set(name, Value::Unknown);
        }
        return;
    }
    if matches!(kind, "block" | "statement_block" | "compound_statement") {
        let mut local = env.clone();
        for child in children(node) {
            visit(language, child, source, &mut local, result);
        }
        env.merge_possible(&local);
        return;
    }
    if matches!(language, Language::Python)
        && matches!(kind, "import_statement" | "import_from_statement")
    {
        python_import(node, source, env);
        return;
    }
    if matches!(language, Language::Go) && kind == "import_spec" {
        if let (Some(name), Some(path)) = (
            field_text(node, "name", source),
            node.child_by_field_name("path")
                .and_then(|path| env.string(path, source)),
        ) {
            env.set(
                name,
                Value::Callable(path.rsplit('/').next().unwrap_or(&path).to_owned()),
            );
        }
        return;
    }
    let fields = match kind {
        "assignment"
        | "assignment_expression"
        | "assignment_statement"
        | "augmented_assignment"
        | "augmented_assignment_expression"
        | "compound_assignment_expr" => Some(("left", "right")),
        "variable_declarator" | "var_spec" => Some(("name", "value")),
        "short_var_declaration" => Some(("left", "right")),
        "let_declaration" => Some(("pattern", "value")),
        "init_declarator" => Some(("declarator", "value")),
        _ => None,
    };
    if let Some((left, right)) = fields
        && let Some(name_node) = node.child_by_field_name(left)
    {
        let value = node
            .child_by_field_name(right)
            .map(|value| {
                let value = if value.kind() == "expression_list" && children(value).len() == 1 {
                    children(value)[0]
                } else {
                    value
                };
                if kind.contains("augmented")
                    || kind.contains("compound")
                    || field_text(node, "operator", source).is_some_and(|op| op != "=")
                {
                    Value::Unknown
                } else {
                    env.value(value, source)
                }
            })
            .unwrap_or(Value::Unknown);
        for child in children(node) {
            visit(language, child, source, env, result);
        }
        if let Some(name) = binding_name(name_node, source) {
            env.set(name, value);
        } else {
            env.invalidate();
            invalidate_names(name_node, source, env);
        }
        return;
    }
    if matches!(
        kind,
        "delete_statement" | "global_statement" | "nonlocal_statement" | "update_expression"
    ) {
        for child in children(node) {
            visit(language, child, source, env, result);
        }
        env.invalidate();
        invalidate_names(node, source, env);
        return;
    }
    if !matches!(kind, "call" | "call_expression") {
        for child in children(node) {
            visit(language, child, source, env, result);
        }
        return;
    }
    let call = node
        .child_by_field_name("function")
        .and_then(|function| env.callee(function, source));
    let receiver_path = node
        .child_by_field_name("function")
        .and_then(|n| n.child_by_field_name("object"))
        .and_then(|n| env.string(n, source));
    let args = node
        .child_by_field_name("arguments")
        .map(children)
        .unwrap_or_default();
    // Resolve the callable before arguments, and capture each argument at its
    // evaluation point. A later argument must not erase an earlier known path.
    if let Some(function) = node.child_by_field_name("function") {
        visit(language, function, source, env, result);
    }
    let mut values = Vec::new();
    for arg in &args {
        let value = if arg.kind() == "keyword_argument" {
            arg.child_by_field_name("value").unwrap_or(*arg)
        } else {
            *arg
        };
        values.push(env.string(value, source));
        visit(language, *arg, source, env, result);
    }
    let Some(call) = call else {
        env.invalidate();
        return;
    };
    let Some((kind, recursive)) = model(language, &call, &args, &values, source) else {
        if !matches!(
            call.as_str(),
            "print"
                | "console.log"
                | "fmt.Println"
                | "fmt.Print"
                | "fmt.Printf"
                | "require"
                | "std::process::Command::new"
                | "exec.Command"
                | "pathlib.Path"
        ) {
            env.invalidate();
        }
        return;
    };
    let file_effect = matches!(
        kind,
        EffectKind::FileRead
            | EffectKind::FileWrite
            | EffectKind::FileDelete
            | EffectKind::PermissionChange
    );
    let copying = matches!(
        call.as_str(),
        "shutil.copy"
            | "shutil.copy2"
            | "shutil.copyfile"
            | "shutil.copytree"
            | "shutil.move"
            | "os.rename"
            | "os.replace"
    );
    let path = if call.starts_with("pathlib.Path.") {
        receiver_path
    } else {
        file_effect
            .then(|| {
                argument(
                    &args,
                    &values,
                    usize::from(copying),
                    if copying { "dst" } else { "file" },
                    source,
                )
            })
            .flatten()
    };
    let mode = open_mode(&args, &values, source);
    let append = call.contains("append") || mode.as_ref().is_some_and(|mode| mode.contains('a'));
    result.push(Observation {
        kind,
        call: call.clone(),
        path: path.clone(),
        recursive,
        append,
        line: node.start_position().row + 1,
        column: node.start_position().column + 1,
    });
    if copying {
        result.push(Observation {
            kind: if matches!(call.as_str(), "shutil.move" | "os.rename" | "os.replace") {
                EffectKind::FileDelete
            } else {
                EffectKind::FileRead
            },
            call: call.clone(),
            path: argument(&args, &values, 0, "src", source),
            recursive: call == "shutil.copytree",
            append: false,
            line: node.start_position().row + 1,
            column: node.start_position().column + 1,
        });
    }
    // An unresolved fopen/open mode can read or write. Never default it to read-only.
    if matches!(call.as_str(), "open" | "fopen" | "std::fopen")
        && (mode.is_none() || mode.as_ref().is_some_and(|mode| mode.contains('+')))
    {
        let additional = if kind == EffectKind::FileRead {
            EffectKind::FileWrite
        } else {
            EffectKind::FileRead
        };
        result.push(Observation {
            kind: additional,
            call,
            path,
            recursive: false,
            append: false,
            line: node.start_position().row + 1,
            column: node.start_position().column + 1,
        });
    }
    if kind == EffectKind::Execute {
        env.invalidate();
    }
}

fn parameter_names(node: Node<'_>, source: &str, env: &mut Environment) {
    if node.kind() == "identifier" {
        env.set(text(node, source), Value::Unknown);
        return;
    }
    if let Some(pattern) = node
        .child_by_field_name("name")
        .or_else(|| node.child_by_field_name("pattern"))
        .or_else(|| node.child_by_field_name("declarator"))
    {
        invalidate_names(pattern, source, env);
    } else {
        for child in children(node) {
            if !matches!(
                child.kind(),
                "call" | "call_expression" | "attribute" | "member_expression"
            ) {
                parameter_names(child, source, env);
            }
        }
    }
}

fn invalidate_names(node: Node<'_>, source: &str, env: &mut Environment) {
    if node.kind() == "identifier" {
        env.set(text(node, source), Value::Unknown);
    }
    for child in children(node) {
        invalidate_names(child, source, env);
    }
}

fn python_import(node: Node<'_>, source: &str, env: &mut Environment) {
    let module = field_text(node, "module_name", source);
    for child in children(node) {
        if Some(text(child, source)) == module {
            continue;
        }
        let (name, alias) = if child.kind() == "aliased_import" {
            let Some(name) = field_text(child, "name", source) else {
                continue;
            };
            (name, field_text(child, "alias", source).unwrap_or(name))
        } else if matches!(child.kind(), "dotted_name" | "identifier") {
            let name = text(child, source);
            (name, name.split('.').next().unwrap_or(name))
        } else {
            continue;
        };
        let canonical = module
            .map(|module| format!("{module}.{name}"))
            .unwrap_or_else(|| name.to_owned());
        env.set(alias, Value::Callable(canonical));
    }
}

fn argument(
    args: &[Node<'_>],
    values: &[Option<String>],
    position: usize,
    keyword: &str,
    source: &str,
) -> Option<String> {
    if let Some(index) = args.iter().position(|arg| {
        arg.kind() == "keyword_argument" && field_text(*arg, "name", source) == Some(keyword)
    }) {
        return values[index].clone();
    }
    args.iter()
        .enumerate()
        .filter(|(_, arg)| arg.kind() != "keyword_argument")
        .nth(position)
        .and_then(|(index, _)| values[index].clone())
}

fn open_mode(args: &[Node<'_>], values: &[Option<String>], source: &str) -> Option<String> {
    let supplied = args
        .iter()
        .filter(|arg| arg.kind() != "keyword_argument")
        .count()
        > 1
        || args
            .iter()
            .any(|arg| field_text(*arg, "name", source) == Some("mode"));
    if supplied {
        argument(args, values, 1, "mode", source)
    } else {
        Some("r".into())
    }
}

fn model(
    language: Language,
    call: &str,
    args: &[Node<'_>],
    values: &[Option<String>],
    source: &str,
) -> Option<(EffectKind, bool)> {
    let supported = match language {
        Language::Python => {
            call.starts_with("pathlib.Path.")
                || matches!(
                    call,
                    "open"
                        | "os.remove"
                        | "os.unlink"
                        | "shutil.rmtree"
                        | "eval"
                        | "exec"
                        | "os.system"
                        | "subprocess.run"
                        | "subprocess.Popen"
                        | "requests.get"
                        | "requests.post"
                        | "shutil.copy"
                        | "shutil.copy2"
                        | "shutil.copyfile"
                        | "shutil.copytree"
                        | "shutil.move"
                        | "os.rename"
                        | "os.replace"
                        | "os.chmod"
                        | "os.chown"
                        | "subprocess.call"
                        | "subprocess.check_call"
                        | "subprocess.check_output"
                        | "os.popen"
                        | "urllib.request.urlopen"
                        | "urllib.request.urlretrieve"
                        | "unittest.main"
                        | "pytest.main"
                        | "doctest.testmod"
                        | "doctest.testfile"
                )
        }
        Language::JavaScript => {
            call.starts_with("fs.")
                || call.starts_with("child_process.")
                || matches!(call, "eval" | "fetch" | "http.request" | "https.request")
        }
        Language::Go => {
            call.starts_with("os.")
                || call.starts_with("http.")
                || call.starts_with("process_builder.")
                || call == "ioutil.ReadFile"
        }
        Language::C | Language::Cpp => matches!(
            call,
            "fopen"
                | "std::fopen"
                | "remove"
                | "std::remove"
                | "unlink"
                | "system"
                | "std::system"
                | "std::filesystem::remove"
                | "std::filesystem::remove_all"
        ),
        Language::Rust => call.starts_with("std::fs::") || call.starts_with("process_builder."),
        Language::Java => false,
    };
    if !supported {
        return None;
    }
    let (kind, recursive) = match call {
        "open" | "fopen" | "std::fopen" => {
            let mode = open_mode(args, values, source);
            let writes = mode
                .as_deref()
                .is_some_and(|mode| mode.contains(['w', 'a', 'x', '+']));
            (
                if writes {
                    EffectKind::FileWrite
                } else {
                    EffectKind::FileRead
                },
                false,
            )
        }
        "fs.readFile"
        | "fs.readFileSync"
        | "os.ReadFile"
        | "ioutil.ReadFile"
        | "std::fs::read"
        | "std::fs::read_to_string" => (EffectKind::FileRead, false),
        "pathlib.Path.read_text" | "pathlib.Path.read_bytes" => (EffectKind::FileRead, false),
        "pathlib.Path.write_text"
        | "pathlib.Path.write_bytes"
        | "pathlib.Path.touch"
        | "pathlib.Path.mkdir" => (EffectKind::FileWrite, false),
        "pathlib.Path.unlink" | "pathlib.Path.rmdir" => (EffectKind::FileDelete, false),
        "shutil.copy" | "shutil.copy2" | "shutil.copyfile" | "shutil.copytree" | "shutil.move"
        | "os.rename" | "os.replace" => (EffectKind::FileWrite, false),
        "os.chmod" | "os.chown" | "pathlib.Path.chmod" => (EffectKind::PermissionChange, false),
        "fs.writeFile" | "fs.writeFileSync" | "fs.appendFileSync" | "os.WriteFile"
        | "std::fs::write" => (EffectKind::FileWrite, false),
        "os.remove"
        | "os.unlink"
        | "fs.unlink"
        | "fs.unlinkSync"
        | "os.Remove"
        | "std::fs::remove_file"
        | "unlink"
        | "remove"
        | "std::remove"
        | "std::filesystem::remove" => (EffectKind::FileDelete, false),
        "fs.rm" | "fs.rmSync" => (EffectKind::FileDelete, recursive_option(args, source)),
        "shutil.rmtree"
        | "os.RemoveAll"
        | "std::fs::remove_dir_all"
        | "std::filesystem::remove_all" => (EffectKind::FileDelete, true),
        "eval"
        | "exec"
        | "os.system"
        | "subprocess.run"
        | "subprocess.Popen"
        | "subprocess.call"
        | "subprocess.check_call"
        | "subprocess.check_output"
        | "unittest.main"
        | "pytest.main"
        | "doctest.testmod"
        | "doctest.testfile"
        | "os.popen"
        | "child_process.exec"
        | "child_process.execSync"
        | "child_process.spawn"
        | "process_builder.Run"
        | "process_builder.Start"
        | "process_builder.Output"
        | "process_builder.CombinedOutput"
        | "process_builder.status"
        | "process_builder.spawn"
        | "process_builder.output"
        | "system"
        | "std::system" => (EffectKind::Execute, false),
        "fetch"
        | "requests.get"
        | "requests.post"
        | "http.Get"
        | "http.Post"
        | "http.request"
        | "https.request"
        | "urllib.request.urlopen"
        | "urllib.request.urlretrieve" => (EffectKind::Connect, false),
        _ => return None,
    };
    Some((kind, recursive))
}

fn recursive_option(args: &[Node<'_>], source: &str) -> bool {
    let Some(options) = args.get(1) else {
        return false;
    };
    // Unknown options may enable recursive deletion; observations are conditional.
    if options.kind() != "object" {
        return true;
    }
    let mut recursive = false;
    for pair in children(*options) {
        if pair.kind() != "pair" {
            return true;
        }
        let Some(key) = pair.child_by_field_name("key") else {
            return true;
        };
        if !matches!(key.kind(), "property_identifier" | "string") {
            return true;
        }
        if matches!(
            text(key, source),
            "recursive" | "\"recursive\"" | "'recursive'"
        ) {
            recursive = field_text(pair, "value", source) != Some("false");
        }
    }
    recursive
}
