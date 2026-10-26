use super::*;
use distill_core::EffectKind;

fn recognized(language: Language, source: &str) -> bool {
    analyze(language, source).is_ok_and(|analysis| analysis.print_only)
}

#[test]
fn python_tracks_primitive_bindings_and_arithmetic() {
    for source in [
        "value = (1 + 2) * 3\nprint(value)",
        "text = '''hello; # still a string'''\nprint(text)",
        "print(\n  'http://example.com/*text*/',\n  end='\\n',\n) # harmless",
    ] {
        assert!(recognized(Language::Python, source), "{source}");
    }
}

#[test]
fn python_does_not_trust_shadowed_functions_or_unknown_values() {
    for source in [
        "print = 1\nprint('hello')",
        "value: unknown() = 1\nprint(value)",
        "value = open('data').read()\nprint(value)",
        "print(missing)",
        "print(f'{unknown()}')",
        "print(1); import os",
        "print(*unknown())",
        "print(1, file=open('data', 'w'))",
    ] {
        assert!(!recognized(Language::Python, source), "{source}");
    }
}

#[test]
fn javascript_tracks_primitives_and_real_comments() {
    for source in [
        "/* comment */ const value = (1 + 2) * 3; console.log(value);",
        "const url = 'http://example.com/*text*/'; console /* comment */ . log(url);",
        "console.log(\n  1, true, null,\n); // harmless",
    ] {
        assert!(recognized(Language::JavaScript, source), "{source}");
    }
}

#[test]
fn javascript_rejects_calls_getters_and_shadowing() {
    for source in [
        "const console = {}; console.log(1);",
        "const value = { get x() { return process.cwd(); } }; console.log(value.x);",
        "console.log((unknown(), 1));",
        "console['log'](unknown());",
        "console.log(`${unknown()}`);",
        "console.log(1); /* comment */ require('fs');",
        "console.log(...unknown());",
        "Object.defineProperty(console, 'log', {value: unknown}); console.log(1);",
    ] {
        assert!(!recognized(Language::JavaScript, source), "{source}");
    }
}

#[test]
fn native_programs_are_independent_of_layout_and_comments() {
    for (language, source) in [
        (
            Language::Go,
            "package main\nimport (\"fmt\")\nfunc main(){ /* comment */ fmt.Println(\"http://example.com\") }",
        ),
        (
            Language::C,
            "#include <stdio.h>\nint main(void){ /* comment */ puts(\"http://example.com\"); return 0; }",
        ),
        (
            Language::Cpp,
            "#include <iostream>\nint main(){ /* comment */ std::cout << \"http://example.com\" << std::endl; return 0; }",
        ),
        (
            Language::Rust,
            "fn main(){ /* comment */ println!(\"http://example.com\"); }",
        ),
    ] {
        assert!(recognized(language, source), "{language:?}: {source}");
    }
}

#[test]
fn native_comments_cannot_hide_extra_code() {
    for (language, source) in [
        (
            Language::Go,
            "package main\nimport \"fmt\"\nimport \"os\" /* comment */\nfunc main(){ fmt.Println(\"hi\") }",
        ),
        (
            Language::C,
            "#include <stdio.h>\nint main(void){ puts(\"hi\"); getchar(); /* comment */ return 0; }",
        ),
        (
            Language::Cpp,
            "#include <iostream>\nint main(){ std::cout << \"hi\"; std::cin.get(); /* comment */ return 0; }",
        ),
        (
            Language::Rust,
            "fn main(){ println!(\"hi\"); std::env::current_dir(); /* comment */ }",
        ),
    ] {
        assert!(!recognized(language, source), "{language:?}: {source}");
    }
}

#[test]
fn c_printf_accepts_plain_escapes_and_rejects_encoded_conversions() {
    for format in ["hello\\n", "100%%", "hello\\tworld"] {
        let source =
            format!("#include <stdio.h>\nint main(void){{ printf(\"{format}\"); return 0; }}");
        assert!(recognized(Language::C, &source), "{source}");
    }
    for format in ["%n", "\\x25n", "\\045n", "??/x25n", "%s"] {
        let source =
            format!("#include <stdio.h>\nint main(void){{ printf(\"{format}\"); return 0; }}");
        assert!(!recognized(Language::C, &source), "{source}");
    }
}

#[test]
fn native_global_initializers_macros_and_extra_functions_are_unresolved() {
    for (language, source) in [
        (
            Language::Go,
            "package main\nimport \"fmt\"\nfunc init(){ unknown() }\nfunc main(){ fmt.Println(\"hi\") }",
        ),
        (
            Language::Cpp,
            "#include <iostream>\nint x = unknown();\nint main(){ std::cout << \"hi\"; }",
        ),
        (
            Language::Cpp,
            "#include <iostream>\n#define cout unknown\nint main(){ std::cout << \"hi\"; }",
        ),
        (
            Language::Rust,
            "macro_rules! println { ($x:expr) => { unknown() } }\nfn main(){ println!(\"hi\"); }",
        ),
        (
            Language::C,
            "#include <stdio.h>\nint main(void){ printf(\"%n\", 0); return 0; }",
        ),
        (
            Language::C,
            "#include <stdio.h>\nint main(void){ printf(\"\\x25n\"); return 0; }",
        ),
    ] {
        assert!(!recognized(language, source), "{language:?}: {source}");
    }
}

#[test]
fn syntax_errors_and_limits_never_produce_a_print_only_proof() {
    assert!(!recognized(Language::Python, "print('hello'"));
    assert!(!recognized(Language::JavaScript, "console.log('hello') +"));
    assert!(analyze(Language::Python, &" ".repeat(65537)).is_err());
    let deep = format!("print({}1{})", "(".repeat(100), ")".repeat(100));
    assert!(!recognized(Language::Python, &deep));
}

#[test]
fn file_effects_include_source_positions_without_running_the_program() {
    let analysis = analyze(
        Language::Python,
        "print(1)\nprint(open('/etc/passwd').read())",
    )
    .unwrap();
    assert!(!analysis.print_only);
    let read = analysis
        .observations
        .iter()
        .find(|item| item.kind == EffectKind::FileRead)
        .unwrap();
    assert_eq!(read.path.as_deref(), Some("/etc/passwd"));
    assert_eq!(read.line, 2);
    assert_eq!(read.column, 7);
    let js = analyze(
        Language::JavaScript,
        "const fs = require('node:fs'); fs.readFileSync('/etc/passwd');",
    )
    .unwrap();
    assert!(js.observations.iter().any(
        |item| item.kind == EffectKind::FileRead && item.path.as_deref() == Some("/etc/passwd")
    ));
}

#[test]
fn operations_in_strings_and_comments_are_inert() {
    for (language, source) in [
        (
            Language::Python,
            "print(\"open('/etc/passwd')\") # os.remove('/')",
        ),
        (
            Language::JavaScript,
            "console.log(\"require('fs').rmSync('/')\"); /* fetch('x') */",
        ),
    ] {
        let analysis = analyze(language, source).unwrap();
        assert!(analysis.print_only);
        assert!(analysis.observations.is_empty());
    }
}

#[test]
fn local_paths_propagate_in_every_parsed_language() {
    for (language, source) in [
        (
            Language::Python,
            "base = '/etc'; path = base + '/passwd'; print(open(path).read())",
        ),
        (
            Language::JavaScript,
            "const fs = require('node:fs'); const base = '/etc'; const path = base + '/passwd'; fs.readFileSync(path);",
        ),
        (
            Language::Go,
            "package main\nimport \"os\"\nfunc main(){ base := \"/etc\"; path := base + \"/passwd\"; os.ReadFile(path) }",
        ),
        (
            Language::C,
            "#include <stdio.h>\nint main(void){ const char *path = \"/etc/passwd\"; fopen(path, \"r\"); }",
        ),
        (
            Language::Cpp,
            "#include <cstdio>\nint main(){ const char *path = \"/etc/passwd\"; fopen(path, \"r\"); }",
        ),
        (
            Language::Rust,
            "fn main(){ let base = \"/etc\"; let path = \"/etc/passwd\"; std::fs::read(path); }",
        ),
        (
            Language::Rust,
            "fn main(){ let path = \"/etc/passwd\"; std::fs::read(&path); }",
        ),
    ] {
        let analysis = analyze(language, source).unwrap();
        assert!(!analysis.print_only);
        assert!(
            analysis
                .observations
                .iter()
                .any(|item| item.kind == EffectKind::FileRead
                    && item.path.as_deref() == Some("/etc/passwd")),
            "{language:?}: {source}\n{}",
            parse(language, source, &distill_core::AnalysisBudget::new(100))
                .unwrap()
                .root_node()
                .to_sexp()
        );
    }
}

#[test]
fn module_and_function_aliases_are_ordered_and_reassignment_invalidates_them() {
    for (language, source) in [
        (
            Language::Python,
            "import shutil as files\npath = '/'\nremove = files.rmtree\nremove(path)",
        ),
        (
            Language::Python,
            "from shutil import rmtree as remove\npath = '/'\nremove(path)",
        ),
        (
            Language::JavaScript,
            "const files = require('fs'); const remove = files.rmSync; const path = '/'; remove(path, {recursive: true});",
        ),
        (
            Language::Go,
            "package main\nimport files \"os\"\nfunc main(){ path := \"/\"; files.RemoveAll(path) }",
        ),
    ] {
        let analysis = analyze(language, source).unwrap();
        assert!(
            analysis
                .observations
                .iter()
                .any(|item| item.kind == EffectKind::FileDelete
                    && item.recursive
                    && item.path.as_deref() == Some("/")),
            "{language:?}: {source}"
        );
    }
    for source in [
        "const files = require('fs'); files = other; files.rmSync('/', {recursive: true});",
        "files.rmSync('/', {recursive: true}); const files = require('fs');",
        "const files = require('fs'); const remove = files.rmSync; remove = other; remove('/', {recursive: true});",
    ] {
        assert!(
            analyze(Language::JavaScript, source)
                .unwrap()
                .observations
                .is_empty(),
            "{source}"
        );
    }
}

#[test]
fn unresolved_assignments_branches_and_calls_cannot_supply_stale_paths() {
    for (language, source) in [
        (Language::Python, "path = '/'\npath = unknown\nopen(path)"),
        (
            Language::Python,
            "path = '/'\nif flag:\n    path = '/tmp/file'\nopen(path)",
        ),
        (Language::Python, "path = '/'\nmutate()\nopen(path)"),
        (Language::Python, "path = '/'\ndel path\nopen(path)"),
        (
            Language::JavaScript,
            "let path = '/'; path = unknown; require('fs').readFileSync(path);",
        ),
        (
            Language::JavaScript,
            "let path = 'tmp'; path += '/'; require('fs').readFileSync(path);",
        ),
        (
            Language::JavaScript,
            "let path = '/'; if (flag) { path = '/tmp/file'; } require('fs').readFileSync(path);",
        ),
    ] {
        let analysis = analyze(language, source).unwrap();
        assert!(
            analysis.observations.iter().all(|item| item.path.is_none()),
            "{language:?}: {source}"
        );
    }
    for source in [
        "path = '/'; path = '/tmp/file'; open(path)",
        "path = '/'; def_unused = 1; open(path) # unrelated binding",
    ] {
        let analysis = analyze(Language::Python, source).unwrap();
        assert!(
            analysis.observations.iter().any(|item| item.path.is_some()),
            "{source}"
        );
    }
}

#[test]
fn function_parameters_shadow_outer_paths_and_defaults_are_inspected() {
    let source = "path = '/'\ndef inspect(path):\n    open(path)\nopen(path)";
    let analysis = analyze(Language::Python, source).unwrap();
    let reads: Vec<_> = analysis
        .observations
        .iter()
        .filter(|item| item.kind == EffectKind::FileRead)
        .collect();
    assert_eq!(reads.len(), 2);
    assert_eq!(reads[0].path, None);
    assert_eq!(reads[1].path.as_deref(), Some("/"));
    let defaults = analyze(
        Language::Python,
        "import shutil\ndef f(value=shutil.rmtree('/')):\n    print(value)",
    )
    .unwrap();
    assert!(
        defaults
            .observations
            .iter()
            .any(|item| item.kind == EffectKind::FileDelete && item.path.as_deref() == Some("/"))
    );
}

#[test]
fn open_modes_follow_bindings_and_unknown_modes_include_possible_writes() {
    let analysis = analyze(
        Language::Python,
        "path = 'out'; mode = 'a'; open(path, mode)",
    )
    .unwrap();
    assert!(
        analysis
            .observations
            .iter()
            .any(|item| item.kind == EffectKind::FileWrite && item.append)
    );
    let analysis = analyze(Language::Python, "open('out', unknown)").unwrap();
    assert!(
        analysis
            .observations
            .iter()
            .any(|item| item.kind == EffectKind::FileWrite)
    );
    let keyword = analyze(Language::Python, "open(file='out', mode=unknown)").unwrap();
    assert!(
        keyword
            .observations
            .iter()
            .any(|item| item.kind == EffectKind::FileWrite && item.path.as_deref() == Some("out"))
    );
    let update = analyze(Language::C, "int main(){ fopen(\"out\", \"r+\"); }").unwrap();
    assert!(
        update
            .observations
            .iter()
            .any(|item| item.kind == EffectKind::FileRead)
    );
    assert!(
        update
            .observations
            .iter()
            .any(|item| item.kind == EffectKind::FileWrite)
    );
}

#[test]
fn harmless_branches_preserve_aliases_and_loop_bindings_shadow_outer_values() {
    let branch = analyze(
        Language::Python,
        "import shutil\nif flag:\n    print(1)\nshutil.rmtree('/')",
    )
    .unwrap();
    assert!(
        branch
            .observations
            .iter()
            .any(|item| item.kind == EffectKind::FileDelete && item.path.as_deref() == Some("/"))
    );
    let looped = analyze(
        Language::Python,
        "path = '/'\nfor path in paths:\n    open(path)",
    )
    .unwrap();
    assert!(looped.observations.iter().all(|item| item.path.is_none()));
}

#[test]
fn callable_and_earlier_argument_are_captured_before_later_side_effects() {
    let analysis = analyze(
        Language::JavaScript,
        "const fs = require('fs'); const path = '/'; fs.rmSync(path, changeOptions());",
    )
    .unwrap();
    assert!(
        analysis
            .observations
            .iter()
            .any(|item| item.kind == EffectKind::FileDelete
                && item.path.as_deref() == Some("/")
                && item.recursive)
    );
}
