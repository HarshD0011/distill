//! Semantic properties and contrasting controls; candidate programs are never run.
use distill_core::{
    AnalyzeRequest, CommandForm, CommandKind, Config, CoverageSummary, DatabaseAction,
    DatabaseScope, Decision, EffectKind, Integration, Report, Severity, ShellDialect,
};
fn request(command: &str) -> AnalyzeRequest {
    AnalyzeRequest {
        protocol_version: 1,
        request_id: "semantic".into(),
        command: CommandForm {
            kind: CommandKind::Shell,
            text: command.into(),
            dialect: ShellDialect::Bash,
        },
        cwd: "/tmp".into(),
        session_id: None,
        source: Integration::Cli,
        budget_ms: 900,
        context: Default::default(),
    }
}
fn score(request: &AnalyzeRequest, config: &Config) -> Report {
    distill_rules::score(request, crate::interpret(request, config), config, 0)
}
fn report(command: &str) -> Report {
    score(&request(command), &Config::default())
}
fn quoted(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\"'\"'"))
}
fn psql(s: &str) -> String {
    format!("psql -X -c {}", quoted(s))
}
fn scope(report: &Report) -> DatabaseScope {
    report
        .behaviors
        .iter()
        .filter_map(|b| b.database)
        .find(|b| b.action == DatabaseAction::Delete)
        .unwrap()
        .scope
}

#[test]
fn constant_predicate_families_survive_sql_composition() {
    for predicate in [
        "TRUE",
        "9 = 9",
        "NOT FALSE",
        "2 * 3 = 6",
        "FALSE OR TRUE",
        "TRUE AND TRUE",
        "NULL OR TRUE",
        "TRUE OR id = 2",
    ] {
        for table in ["orders", "\"unrelated-table\"", "public.accounts"] {
            let deletion = format!("DELETE FROM {table} WHERE ({predicate})");
            for sql in [
                deletion.clone(),
                format!("WITH gone AS ({deletion} RETURNING *) SELECT 1 WHERE FALSE"),
                format!("EXPLAIN (ANALYZE true) {deletion}"),
            ] {
                let r = report(&psql(&sql));
                assert_eq!(
                    r.impact_severity,
                    Some(Severity::Critical),
                    "{sql}: {:?}",
                    r.unknowns
                );
                assert_eq!(scope(&r), DatabaseScope::AllRows, "{sql}");
                assert!(
                    !r.effects.iter().any(|e| e.kind == EffectKind::FileDelete),
                    "SQL must not become filesystem deletion"
                );
            }
        }
    }
}

#[test]
fn null_predicates_and_unknown_analysis_are_different() {
    for (predicate, expected) in [
        ("FALSE", DatabaseScope::NoRows),
        ("NULL", DatabaseScope::NoRows),
        ("1=0", DatabaseScope::NoRows),
        ("NULL AND TRUE", DatabaseScope::NoRows),
        ("NOT NULL", DatabaseScope::NoRows),
        ("NULL IS NULL", DatabaseScope::AllRows),
        ("id=id", DatabaseScope::ConditionalRows),
        ("id=7", DatabaseScope::ConditionalRows),
        ("1/0=1", DatabaseScope::Unresolved),
        ("2147483647 + 1=0", DatabaseScope::Unresolved),
        ("unknown_function()", DatabaseScope::Unresolved),
        ("CAST('1' AS INT)=1", DatabaseScope::Unresolved),
    ] {
        let r = report(&psql(&format!("DELETE FROM accounts WHERE {predicate}")));
        assert_eq!(scope(&r), expected, "{predicate}");
        assert_ne!(r.decision, Decision::Allow);
    }
}

#[test]
fn plan_only_and_data_text_do_not_execute_nested_operations() {
    for sql in [
        "EXPLAIN DELETE FROM accounts",
        "EXPLAIN (ANALYZE FALSE) DELETE FROM accounts",
        "EXPLAIN (ANALYZE off) WITH gone AS (DELETE FROM accounts RETURNING *) SELECT * FROM gone",
        "SELECT 'DELETE FROM accounts; DROP TABLE users'",
        "SELECT $$\\! rm -rf /$$",
        "SELECT \"DROP\" FROM accounts",
        "PREPARE later AS DELETE FROM accounts",
    ] {
        let r = report(&psql(sql));
        assert_eq!(
            r.impact_severity,
            Some(Severity::Medium),
            "{sql}: {:?}",
            r.unknowns
        );
        assert!(!r.behaviors.iter().any(|b| {
            b.database
                .is_some_and(|d| d.action == DatabaseAction::Delete)
        }));
    }
    let r = report(&psql(
        "WITH unused AS (DELETE FROM accounts RETURNING *) SELECT 1 WHERE FALSE",
    ));
    assert_eq!(r.impact_severity, Some(Severity::Critical));
}

#[test]
fn malformed_later_sql_preserves_prior_executable_effects() {
    for sql in [
        "DROP TABLE accounts; this is not SQL",
        "DELETE FROM accounts; SELECT 'unterminated",
    ] {
        let r = report(&psql(sql));
        assert_eq!(r.impact_severity, Some(Severity::Critical));
        assert_ne!(r.coverage.summary, CoverageSummary::StaticAccounted);
    }
}

#[test]
fn file_roles_and_custom_policy_do_not_depend_on_command_spelling() {
    for destination in [".env", "nested/.env.local", ".ssh/id_ed25519"] {
        for command in [
            format!("git diff --output={destination}"),
            format!("git diff --output {}", quoted(destination)),
            format!("git diff --no-index -- input.txt {}", quoted(destination)),
            format!("psql -X --file={destination}"),
        ] {
            let r = report(&command);
            assert_eq!(
                r.impact_severity,
                Some(Severity::High),
                "{command}: {:?}",
                r.unknowns
            );
            assert!(
                r.behaviors
                    .iter()
                    .any(|b| b.target_class == distill_core::TargetClass::Secret)
            );
        }
    }
    let mut config = Config::default();
    config.policy.effects.database_all_rows = Severity::High;
    config.validate().unwrap();
    let r = score(
        &request(&psql("DELETE FROM any_table WHERE 3*7=21")),
        &config,
    );
    assert_eq!(r.impact_severity, Some(Severity::High));
    assert_eq!(scope(&r), DatabaseScope::AllRows);
}

#[test]
fn unknown_option_arity_never_rebinds_a_later_payload() {
    for command in [
        "psql --unknown -c 'DROP TABLE users'",
        "git diff --unknown --output=.env",
    ] {
        let r = report(command);
        assert_ne!(r.coverage.summary, CoverageSummary::StaticAccounted);
        assert!(!r.behaviors.iter().any(|b| {
            b.database
                .is_some_and(|d| d.action == DatabaseAction::SchemaDelete)
        }));
        assert!(!r.behaviors.iter().any(|b| b.kind == EffectKind::FileWrite));
        assert_ne!(r.decision, Decision::Allow);
    }
    let r = report("git diff --output=.env --unknown");
    assert_eq!(r.impact_severity, Some(Severity::High));
    let r = report("git diff --output=.env --output=ordinary.txt");
    assert_eq!(r.impact_severity, Some(Severity::Medium));
    assert_eq!(
        r.behaviors
            .iter()
            .filter(|b| b.kind == EffectKind::FileWrite)
            .count(),
        1
    );
}

#[test]
fn client_shell_handoffs_follow_real_argument_reconstruction() {
    for command in [
        "sqlite3 scratch.db '.shell rm -rf /'",
        "sqlite3 scratch.db '.system rm -rf /'",
        "psql -X -c '\\! rm -rf /'",
    ] {
        let r = report(command);
        assert_eq!(
            r.impact_severity,
            Some(Severity::Critical),
            "{command}: {:?}",
            r.unknowns
        );
    }
    for command in [
        "sqlite3 scratch.db '.shell echo literal'",
        "sqlite3 scratch.db \".shell 'rm -rf /'\"",
        "sqlite3 scratch.db \"SELECT '.shell rm -rf /'\"",
    ] {
        let r = report(command);
        assert_eq!(
            r.impact_severity,
            Some(Severity::Medium),
            "{command}: {:?}",
            r.unknowns
        );
    }
    let command = format!("sqlite3 scratch.db {}", quoted(".shell echo '$(cat .env)'"));
    assert_eq!(report(&command).impact_severity, Some(Severity::High));
    assert!(
        report("psql -L '|rm -rf /'")
            .behaviors
            .iter()
            .any(|b| b.kind == EffectKind::FileWrite && b.append)
    );
    assert_ne!(
        report("psql -L '|rm -rf /'").impact_severity,
        Some(Severity::Critical)
    );
}

#[test]
fn native_capabilities_use_ast_calls_and_retain_uncertainty() {
    for source in [
        "SELECT load_extension('./plugin')",
        "SELECT LOAD_EXTENSION('./renamed')",
        ".load ./other",
        "SELECT load_extension(module_column)",
    ] {
        let r = report(&format!("sqlite3 scratch.db {}", quoted(source)));
        assert_eq!(r.impact_severity, Some(Severity::High));
        assert!(
            r.behaviors
                .iter()
                .any(|b| b.kind == EffectKind::Execute && b.operation == "native_load")
        );
        assert_ne!(r.coverage.summary, CoverageSummary::StaticAccounted);
    }
    for source in [
        "SELECT 'load_extension(./plugin)'",
        "EXPLAIN SELECT load_extension('./plugin')",
    ] {
        let r = report(&format!("sqlite3 scratch.db {}", quoted(source)));
        assert_eq!(r.impact_severity, Some(Severity::Medium));
        assert!(!r.behaviors.iter().any(|b| b.operation == "native_load"));
    }
}

struct Fixture(std::path::PathBuf);
impl Fixture {
    fn new() -> Self {
        let p = std::env::temp_dir().join(distill_core::new_id("semantic-fixture"));
        std::fs::create_dir(&p).unwrap();
        Self(p)
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).unwrap();
    }
}

#[test]
fn source_files_are_hashed_ordered_and_never_read_after_mutation() {
    let root = Fixture::new();
    std::fs::write(root.0.join("input.sql"), "DELETE FROM orders;").unwrap();
    std::fs::write(
        root.0.join("sqlite.sql"),
        "SELECT '.shell rm -rf /\n.load ./plugin';\n.shell cat .env\n",
    )
    .unwrap();
    for command in [
        "psql -X -f input.sql",
        "psql -X --file=input.sql",
        "psql -X -Atfinput.sql",
    ] {
        let mut req = request(command);
        req.cwd = root.0.clone();
        let r = score(&req, &Config::default());
        assert_eq!(r.impact_severity, Some(Severity::Critical));
        assert_eq!(r.inspected_files.len(), 1);
        assert!(r.behaviors.iter().any(|b| {
            b.database
                .is_some_and(|d| d.action == DatabaseAction::Delete)
                && b.location.as_ref().is_some_and(|l| l.file.is_some())
        }));
    }
    let mut req = request("sqlite3 -init sqlite.sql scratch.db");
    req.cwd = root.0.clone();
    let r = score(&req, &Config::default());
    assert_eq!(r.impact_severity, Some(Severity::High));
    assert!(!r.behaviors.iter().any(|b| b.operation == "native_load"));
    let mut req = request("printf 'replacement' > input.sql; psql -f input.sql");
    req.cwd = root.0.clone();
    let r = score(&req, &Config::default());
    assert!(r.unknowns.iter().any(|s| s.contains("modified earlier")));
    assert!(r.inspected_files.is_empty());
}

#[test]
fn nested_client_shell_state_does_not_leak_to_the_outer_shell() {
    let r = report("sqlite3 scratch.db '.shell cd /'; cat input.txt");
    let expected = std::fs::canonicalize("/tmp")
        .unwrap()
        .join("input.txt")
        .to_string_lossy()
        .into_owned();
    assert!(
        r.behaviors
            .iter()
            .any(|b| b.kind == EffectKind::FileRead
                && b.target.as_deref() == Some(expected.as_str()))
    );
}

#[test]
fn client_cycles_and_sql_structure_are_bounded() {
    let root = Fixture::new();
    std::fs::write(root.0.join("cycle.sql"), "\\i cycle.sql\n").unwrap();
    let mut req = request("psql -X -f cycle.sql");
    req.cwd = root.0.clone();
    let r = score(&req, &Config::default());
    assert_eq!(r.coverage.summary, CoverageSummary::Stopped);
    assert_eq!(r.decision, Decision::Deny);
    let sql = format!("SELECT {}", vec!["1"; 1100].join("+"));
    let r = report(&psql(&sql));
    assert_eq!(r.coverage.summary, CoverageSummary::Stopped);
    assert_eq!(r.decision, Decision::Deny);
}
