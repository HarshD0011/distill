use distill_core::{Behavior, EffectKind, EffectPolicy, Severity, TargetClass};

pub struct BehaviorVerdict {
    pub severity: Severity,
    pub rule: &'static str,
    pub impact: &'static str,
}

/// One policy for equivalent operations in every supported language and shell.
/// The caller remains responsible for coverage and unresolved execution risk.
pub fn evaluate_behavior(behavior: &Behavior, policy: &EffectPolicy) -> BehaviorVerdict {
    use EffectKind::*;
    use TargetClass::*;
    if behavior.kind == Database {
        return evaluate_database(behavior, policy);
    }
    if behavior.database.is_some() {
        return BehaviorVerdict {
            severity: policy.unresolved_target,
            rule: "effect.invalid",
            impact: "Effect metadata is inconsistent",
        };
    }
    let (severity, rule, impact) = match (behavior.kind, behavior.target_class) {
        (FileRead | FileWrite, Null) => (Severity::Safe, "io.null", "Accesses the null device"),
        (FileRead, Secret) => (
            policy.sensitive,
            "read.secret",
            "Reads a credential-like path",
        ),
        (FileRead, OutsideWorkspace) => (
            policy.outside_workspace_read,
            "read.outside-workspace",
            "Reads outside the declared workspace roots",
        ),
        (FileWrite | FileDelete, OutsideWorkspace) => (
            policy.outside_workspace_modify,
            "modify.outside-workspace",
            "Modifies a target outside the declared workspace roots",
        ),
        (FileRead, Unresolved) => (
            policy.unresolved_target,
            "read.unresolved",
            "File read target is unresolved",
        ),
        (FileRead, _) => (policy.read, "read.file", "Reads an ordinary file"),
        (FileWrite, Protected) => (
            policy.protected_modify,
            "write.protected",
            "Writes inside a protected or root path",
        ),
        (FileWrite, Secret) => (
            policy.sensitive,
            "write.secret",
            "Writes a credential-like path",
        ),
        (FileWrite, Startup) => (
            policy.startup,
            "write.startup",
            "Writes a file that runs automatically",
        ),
        (FileWrite, Unresolved) => (
            policy.unresolved_target,
            "write.unresolved",
            "Write target could not be resolved",
        ),
        (FileWrite, BuildArtifact) => (
            policy.build_artifact,
            "write.artifact",
            "Creates a compiler output at a currently absent path",
        ),
        (FileWrite, _) if behavior.operation == "mktemp" => (
            policy.write,
            "write.temporary",
            "Creates a temporary file or directory from a literal template",
        ),
        (FileWrite, _) => (
            policy.write,
            "write.file",
            if behavior.append {
                "Output may append to a file"
            } else {
                "Output may create or overwrite a file"
            },
        ),
        (FileDelete, Protected) if behavior.recursive => (
            policy.protected_modify,
            "delete.filesystem-root",
            "Recursive delete targets a protected path, root, or home directory",
        ),
        (FileDelete, Protected) => (
            policy.sensitive,
            "delete.protected",
            "Deletes a protected target",
        ),
        (FileDelete, Secret) => (
            policy.sensitive,
            "delete.secret",
            "Deletes credentials or config",
        ),
        (FileDelete, Startup) => (
            policy.startup,
            "delete.startup",
            "Deletes a file that runs automatically",
        ),
        (FileDelete, Source) => (policy.sensitive, "delete.source", "Deletes source files"),
        (FileDelete, Regenerable) => (
            Severity::Safe,
            "delete.regenerable",
            "Removes regenerable cache files",
        ),
        (FileDelete, Unresolved) => (
            policy.unresolved_target,
            "delete.unresolved",
            "Delete target could not be resolved",
        ),
        (FileDelete, _) if behavior.recursive => (
            policy.recursive_delete,
            "delete.recursive",
            "Recursive delete of ordinary files",
        ),
        (FileDelete, _) => (policy.delete, "delete.file", "Deletes files"),
        (Execute, _) => (
            policy.execute,
            "exec.additional",
            "May execute additional code",
        ),
        (Connect | NetworkSend | NetworkReceive, _) => (
            policy.network,
            "net.connection",
            "May contact a network endpoint",
        ),
        _ => (
            policy.unresolved_target,
            "effect.unresolved",
            "Operation has unresolved impact",
        ),
    };
    BehaviorVerdict {
        severity,
        rule,
        impact,
    }
}

fn evaluate_database(behavior: &Behavior, policy: &EffectPolicy) -> BehaviorVerdict {
    use distill_core::{DatabaseAction as A, DatabaseScope as S};
    let (severity, rule, impact) = match behavior.database {
        Some(distill_core::DatabaseEffect {
            action: A::Query, ..
        }) => (
            policy.database_query,
            "db.query",
            "Database/client operation depends on schema, state and configuration",
        ),
        Some(distill_core::DatabaseEffect {
            action: A::SchemaDelete,
            ..
        }) => (
            policy.database_all_rows,
            "db.schema-delete",
            "Database objects or all their data may be removed",
        ),
        Some(distill_core::DatabaseEffect {
            action: A::SchemaModify,
            ..
        }) => (
            policy.database_modify,
            "db.schema-modify",
            "Database schema or privileges may change",
        ),
        Some(distill_core::DatabaseEffect {
            scope: S::AllRows, ..
        }) => (
            policy.database_all_rows,
            "db.all-rows",
            "Database modification selects all rows before runtime constraints",
        ),
        Some(distill_core::DatabaseEffect {
            scope: S::NoRows, ..
        }) => (
            policy.database_query,
            "db.no-rows",
            "Predicate selects no rows; statement effects and triggers remain unresolved",
        ),
        Some(distill_core::DatabaseEffect {
            scope: S::ConditionalRows,
            ..
        }) => (
            policy.database_modify,
            "db.conditional-rows",
            "Database modification has a row-dependent condition; row count is not bounded",
        ),
        Some(distill_core::DatabaseEffect {
            scope: S::Unresolved,
            ..
        }) => (
            policy.database_unknown_scope,
            "db.unknown-scope",
            "Database modification has unresolved selection scope",
        ),
        None => (
            policy.unresolved_target,
            "db.invalid",
            "Database effect metadata is missing",
        ),
    };
    BehaviorVerdict {
        severity,
        rule,
        impact,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn operation(kind: EffectKind, target_class: TargetClass, recursive: bool) -> Behavior {
        Behavior {
            database: None,
            kind,
            operation: "test".into(),
            target: None,
            target_class,
            recursive,
            append: false,
            location: None,
        }
    }

    #[test]
    fn targets_and_operation_determine_impact() {
        let policy = EffectPolicy::default();
        for (kind, target, recursive, expected) in [
            (
                EffectKind::FileRead,
                TargetClass::Ordinary,
                false,
                Severity::Low,
            ),
            (
                EffectKind::FileRead,
                TargetClass::Secret,
                false,
                Severity::High,
            ),
            (
                EffectKind::FileWrite,
                TargetClass::Startup,
                false,
                Severity::High,
            ),
            (
                EffectKind::FileDelete,
                TargetClass::Ordinary,
                true,
                Severity::Medium,
            ),
            (
                EffectKind::FileDelete,
                TargetClass::Protected,
                true,
                Severity::Critical,
            ),
            (
                EffectKind::FileDelete,
                TargetClass::Unresolved,
                true,
                Severity::High,
            ),
        ] {
            assert_eq!(
                evaluate_behavior(&operation(kind, target, recursive), &policy).severity,
                expected
            );
        }
    }

    #[test]
    fn effect_policy_is_independent_of_language_or_call_spelling() {
        let policy = EffectPolicy {
            read: Severity::Medium,
            ..EffectPolicy::default()
        };
        for call in [
            "open",
            "fs.readFileSync",
            "os.ReadFile",
            "std::fs::read",
            "fopen",
        ] {
            let mut behavior = operation(EffectKind::FileRead, TargetClass::Ordinary, false);
            behavior.operation = call.into();
            assert_eq!(
                evaluate_behavior(&behavior, &policy).severity,
                Severity::Medium
            );
        }
    }

    #[test]
    fn database_policy_rates_scope_independently_of_client_and_target_names() {
        use distill_core::{DatabaseAction as A, DatabaseScope as S};
        let policy = EffectPolicy::default();
        for client in ["psql", "sqlite3", "artifact"] {
            for (action, scope, expected) in [
                (A::Delete, S::AllRows, Severity::Critical),
                (A::Delete, S::NoRows, Severity::Medium),
                (A::Delete, S::ConditionalRows, Severity::High),
                (A::Delete, S::Unresolved, Severity::High),
                (A::SchemaDelete, S::AllRows, Severity::Critical),
            ] {
                let mut behavior = Behavior::database(
                    action,
                    scope,
                    Some(format!("{client}.arbitrary_table")),
                    None,
                );
                behavior.operation = client.into();
                assert_eq!(evaluate_behavior(&behavior, &policy).severity, expected);
                let custom = EffectPolicy {
                    database_all_rows: Severity::High,
                    ..policy.clone()
                };
                if expected == Severity::Critical {
                    assert_eq!(
                        evaluate_behavior(&behavior, &custom).severity,
                        Severity::High
                    );
                }
            }
        }
        let mut inconsistent = operation(EffectKind::FileWrite, TargetClass::Ordinary, false);
        inconsistent.database = Behavior::database(A::Delete, S::AllRows, None, None).database;
        assert_eq!(
            evaluate_behavior(&inconsistent, &policy).rule,
            "effect.invalid"
        );
    }
}
