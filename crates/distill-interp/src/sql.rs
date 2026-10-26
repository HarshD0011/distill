//! Dialect ASTs produce effects. Ratings belong exclusively to distill-rules.
use crate::Analyzer;
use distill_core::{Behavior, DatabaseAction as Action, DatabaseScope as Scope, SourceLocation};
use sqlparser::{
    ast::{
        self, Expr, FromTable, FunctionArg, FunctionArgExpr, FunctionArguments, Spanned, Statement,
        TableFactor, Visit, Visitor,
    },
    dialect::{Dialect, GenericDialect, MySqlDialect, PostgreSqlDialect, SQLiteDialect},
    parser::Parser,
    tokenizer::{Token, Tokenizer},
};
use std::ops::ControlFlow;
mod eval;

#[derive(Clone, Copy, Debug, PartialEq)]
pub(super) enum SqlDialect {
    Postgres,
    Sqlite,
    Mysql,
    Unspecified,
}
impl SqlDialect {
    fn grammar(self) -> Box<dyn Dialect> {
        match self {
            Self::Postgres => Box::new(PostgreSqlDialect {}),
            Self::Sqlite => Box::new(SQLiteDialect {}),
            Self::Mysql => Box::new(MySqlDialect {}),
            Self::Unspecified => Box::new(GenericDialect {}),
        }
    }
    pub(super) fn key(self) -> &'static str {
        match self {
            Self::Postgres => "postgres",
            Self::Sqlite => "sqlite",
            Self::Mysql => "mysql",
            Self::Unspecified => "unspecified",
        }
    }
}

impl Analyzer<'_> {
    pub(super) fn inspect_sql(
        &mut self,
        source: &str,
        dialect: SqlDialect,
        origin: Option<&str>,
        line: usize,
    ) {
        if !self.within_budget() {
            return;
        }
        if source.len() > 64 * 1024 {
            self.stop_analysis("SQL source exceeds the byte limit");
            return;
        }
        let grammar = dialect.grammar();
        let mut tokenizer = Tokenizer::new(grammar.as_ref(), source);
        let mut tokens = Vec::new();
        let tokenized = tokenizer.tokenize_with_location_into_buf(&mut tokens);
        if tokens.len() > 4096 {
            self.stop_analysis("SQL token budget exhausted");
            return;
        }
        for _ in &tokens {
            if !self.budget.visit_node() {
                self.stop_analysis(self.budget.stop_reason());
                return;
            }
        }
        // Significant tokens bound flat operator chains as well as parser recursion.
        let significant = tokens
            .iter()
            .filter(|t| !matches!(t.token, Token::Whitespace(_)))
            .count();
        if significant > 1024 {
            self.stop_analysis("SQL structural token limit exhausted");
            return;
        }
        if !self.within_budget() {
            return;
        }
        if tokenized.is_err() {
            self.unresolved_program("SQL tokenization is incomplete");
        }
        // Recover separate complete statements when a later statement is unsupported.
        // Never use an unrecognized lexical boundary as a recovery delimiter.
        let mut start = 0;
        let mut parens = 0usize;
        for end in 0..=tokens.len() {
            if !self.within_budget() {
                break;
            }
            if let Some(token) = tokens.get(end) {
                match token.token {
                    Token::LParen => parens += 1,
                    Token::RParen => parens = parens.saturating_sub(1),
                    _ => {}
                }
            }
            if end < tokens.len() && !(parens == 0 && matches!(tokens[end].token, Token::SemiColon))
            {
                continue;
            }
            let slice = &tokens[start..end];
            start = end + 1;
            if slice
                .iter()
                .all(|t| matches!(t.token, Token::Whitespace(_)))
            {
                continue;
            }
            if slice.iter().any(|t|matches!(&t.token,Token::Whitespace(sqlparser::tokenizer::Whitespace::MultiLineComment(c)) if c.starts_with('!'))) {
                self.unresolved_program("SQL contains dialect-specific executable comments");
            }
            let parsed = Parser::new(grammar.as_ref())
                .with_recursion_limit(64)
                .with_tokens_with_locations(slice.to_vec())
                .parse_statements();
            if !self.within_budget() {
                break;
            }
            match parsed {
                Ok(statements) => {
                    let mut walker = SqlEffects {
                        analyzer: self,
                        dialect,
                        origin,
                        source,
                        line,
                        execution: vec![true],
                        depth: 0,
                    };
                    for statement in statements {
                        if statement.visit(&mut walker).is_break() {
                            break;
                        }
                    }
                }
                Err(_) => self.unresolved_program(
                    "SQL syntax or dialect construct is outside the supported AST subset",
                ),
            }
        }
    }
}

struct SqlEffects<'a, 'b> {
    analyzer: &'a mut Analyzer<'b>,
    dialect: SqlDialect,
    origin: Option<&'a str>,
    source: &'a str,
    line: usize,
    execution: Vec<bool>,
    depth: usize,
}
impl SqlEffects<'_, '_> {
    fn enter(&mut self) -> ControlFlow<()> {
        self.depth += 1;
        if self.depth > 64 {
            self.analyzer.stop_analysis("SQL AST depth limit exhausted");
            return ControlFlow::Break(());
        }
        if !self.analyzer.budget.visit_node() {
            self.analyzer
                .stop_analysis(self.analyzer.budget.stop_reason());
            return ControlFlow::Break(());
        }
        ControlFlow::Continue(())
    }
    fn location(&self, node: &impl Spanned) -> Option<SourceLocation> {
        let span = node.span();
        (span.start.line > 0).then(|| {
            let line = self
                .source
                .lines()
                .nth(span.start.line as usize - 1)
                .unwrap_or("");
            let column = line
                .char_indices()
                .nth(span.start.column.saturating_sub(1) as usize)
                .map_or(line.len(), |(i, _)| i)
                + 1;
            SourceLocation {
                file: self.origin.map(str::to_owned),
                line: self.line + span.start.line as usize - 1,
                column,
            }
        })
    }
    fn database(
        &mut self,
        action: Action,
        scope: Scope,
        target: Option<String>,
        node: &impl Spanned,
    ) {
        if scope == Scope::Unresolved && matches!(action, Action::Delete | Action::Update) {
            self.analyzer
                .unknown("SQL row-selection scope is unresolved");
        }
        self.analyzer.record_behavior(
            Behavior::database(action, scope, target, self.location(node)),
            None,
        );
    }
    fn explain_executes(&mut self, statement: &Statement) -> bool {
        let Statement::Explain {
            analyze, options, ..
        } = statement
        else {
            return true;
        };
        let mut enabled = *analyze;
        if let Some(options) = options {
            for option in options {
                if option.name.value.eq_ignore_ascii_case("analyze") {
                    enabled = match &option.arg {
                        None => true,
                        Some(expr) => match eval::option_bool(expr, &self.analyzer.budget) {
                            Some(value) => value,
                            None => {
                                self.analyzer
                                    .unresolved_program("EXPLAIN execution option is unresolved");
                                true
                            }
                        },
                    };
                }
            }
        }
        enabled
    }
}
fn table_name(factor: &TableFactor) -> Option<String> {
    if let TableFactor::Table { name, .. } = factor {
        Some(name.to_string())
    } else {
        None
    }
}

impl Visitor for SqlEffects<'_, '_> {
    type Break = ();
    fn pre_visit_statement(&mut self, statement: &Statement) -> ControlFlow<()> {
        self.enter()?;
        if *self.execution.last().unwrap()
            && matches!(
                statement,
                Statement::CreateFunction(_)
                    | Statement::CreateProcedure { .. }
                    | Statement::CreateTrigger(_)
                    | Statement::CreateView(_)
            )
        {
            self.database(Action::SchemaModify, Scope::Unresolved, None, statement);
            self.analyzer
                .unknown("Stored SQL definitions are not executed or proven by this analysis");
        }
        let executing = *self.execution.last().unwrap()
            && self.explain_executes(statement)
            && !matches!(
                statement,
                Statement::Prepare { .. }
                    | Statement::CreateFunction(_)
                    | Statement::CreateProcedure { .. }
                    | Statement::CreateTrigger(_)
                    | Statement::CreateView(_)
            );
        self.execution.push(executing);
        if !executing {
            return ControlFlow::Continue(());
        }
        match statement {
            Statement::Delete(delete) => {
                let mut scope = eval::scope(delete.selection.as_ref(), &self.analyzer.budget);
                if delete.limit.is_some() || delete.using.is_some() {
                    scope = Scope::Unresolved;
                }
                let tables = match &delete.from {
                    FromTable::WithFromKeyword(t) | FromTable::WithoutKeyword(t) => t,
                };
                for table in tables {
                    let table_scope = if table.joins.is_empty() {
                        scope
                    } else {
                        Scope::Unresolved
                    };
                    self.database(
                        Action::Delete,
                        table_scope,
                        table_name(&table.relation),
                        statement,
                    );
                }
            }
            Statement::Update(update) => {
                let mut scope = eval::scope(update.selection.as_ref(), &self.analyzer.budget);
                if update.limit.is_some() || update.from.is_some() || !update.table.joins.is_empty()
                {
                    scope = Scope::Unresolved;
                }
                self.database(
                    Action::Update,
                    scope,
                    table_name(&update.table.relation),
                    statement,
                );
            }
            Statement::Drop { names, .. } => {
                for name in names {
                    self.database(
                        Action::SchemaDelete,
                        Scope::AllRows,
                        Some(name.to_string()),
                        statement,
                    );
                }
            }
            Statement::Truncate(truncate) => {
                for table in &truncate.table_names {
                    self.database(
                        Action::SchemaDelete,
                        Scope::AllRows,
                        Some(table.name.to_string()),
                        statement,
                    );
                }
            }
            Statement::AlterTable(_) | Statement::Revoke(_) => {
                self.database(Action::SchemaModify, Scope::Unresolved, None, statement)
            }
            Statement::Query(_) | Statement::Explain { .. } => {}
            Statement::Call(_) | Statement::Execute { .. } => self
                .analyzer
                .unresolved_program("SQL executes an unresolved procedure or dynamic statement"),
            // The generic visitor still visits children, preserving conditional known effects.
            _ => self
                .analyzer
                .unresolved_program("SQL statement effects are not fully modeled"),
        }
        ControlFlow::Continue(())
    }
    fn post_visit_statement(&mut self, _: &Statement) -> ControlFlow<()> {
        self.execution.pop();
        self.depth -= 1;
        ControlFlow::Continue(())
    }
    fn pre_visit_query(&mut self, _: &ast::Query) -> ControlFlow<()> {
        self.enter()
    }
    fn post_visit_query(&mut self, _: &ast::Query) -> ControlFlow<()> {
        self.depth -= 1;
        ControlFlow::Continue(())
    }
    fn pre_visit_expr(&mut self, expr: &Expr) -> ControlFlow<()> {
        self.enter()?;
        if !*self.execution.last().unwrap() {
            return ControlFlow::Continue(());
        }
        if let Expr::Function(function) = expr {
            let name = if function.name.0.len() == 1 {
                function.name.0[0]
                    .as_ident()
                    .map(|i| i.value.to_ascii_lowercase())
            } else {
                None
            };
            let capability = name
                .as_deref()
                .and_then(|name| crate::client::function_capability(self.dialect.key(), name));
            if let Some(capability) = capability {
                let arg = match &function.args {
                    FunctionArguments::List(list) => list.args.get(capability.argument),
                    _ => None,
                };
                let value = match arg {
                    Some(FunctionArg::Unnamed(FunctionArgExpr::Expr(Expr::Value(v)))) => {
                        match &v.value {
                            ast::Value::SingleQuotedString(s) => Some(s.clone()),
                            _ => None,
                        }
                    }
                    _ => None,
                };
                self.analyzer
                    .language_capability(capability.kind, value, self.location(expr));
            } else {
                self.analyzer
                    .unresolved_program("SQL function identity and effects are unresolved");
            }
        }
        ControlFlow::Continue(())
    }
    fn post_visit_expr(&mut self, _: &Expr) -> ControlFlow<()> {
        self.depth -= 1;
        ControlFlow::Continue(())
    }
}
