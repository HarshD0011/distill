//! Structural shell front end. Candidate code is parsed, never executed.
use std::ops::ControlFlow;

use distill_core::{EffectKind, Severity, ShellDialect};
use distill_parse::{Token, Word, lex};
use tree_sitter::{Node, ParseOptions, Parser};

use crate::{Analyzer, syntax::Language};

/// Standard input with its shell expansion boundary preserved.
pub(super) struct ShellInput {
    pub text: String,
    pub dynamic: bool,
}

impl Analyzer<'_> {
    pub(super) fn analyze(&mut self, source: &str, depth: usize) {
        if !self.within_budget() {
            return;
        }
        if depth > self.config.analysis.expansion_depth_max
            || source.len() > self.config.analysis.command_bytes_max
        {
            self.stop_analysis("Analysis size or nesting limit reached");
            return;
        }
        if self.dialect == ShellDialect::Zsh {
            self.inspect_zsh(source);
        }
        let mut parser = Parser::new();
        if parser
            .set_language(&tree_sitter_bash::LANGUAGE.into())
            .is_err()
        {
            self.syntax_partial = true;
            self.unknown("Bash grammar is unavailable");
            return;
        }
        let mut progress = |_: &tree_sitter::ParseState| {
            if self.budget.expired() {
                ControlFlow::Break(())
            } else {
                ControlFlow::Continue(())
            }
        };
        let tree = parser.parse_with_options(
            &mut |offset, _| source.as_bytes().get(offset..).unwrap_or_default(),
            None,
            Some(ParseOptions::new().progress_callback(&mut progress)),
        );
        let Some(tree) = tree else {
            self.within_budget();
            return;
        };
        // Validate the complete tree budget before recursive helpers inspect word syntax.
        let mut stack = vec![(tree.root_node(), 0)];
        let mut count = 0;
        while let Some((node, level)) = stack.pop() {
            if !self.budget.visit_node() {
                self.within_budget();
                return;
            }
            if !self.within_budget() {
                return;
            }
            count += 1;
            if count > self.config.analysis.graph_nodes_max || level > 64 {
                self.stop_analysis("Shell syntax tree exceeds the analysis limit");
                return;
            }
            stack.extend(children(node).into_iter().map(|child| (child, level + 1)));
        }
        if tree.root_node().has_error() {
            self.syntax_partial = true;
            self.raise(Severity::Medium);
            self.unknown("Shell contains syntax errors or unsupported syntax");
        }
        self.walk_shell(tree.root_node(), source, depth, 0);
    }

    fn walk_shell(&mut self, node: Node<'_>, source: &str, depth: usize, ast_depth: usize) {
        if !self.within_budget() {
            return;
        }
        self.nodes += 1;
        if ast_depth > 64 || self.nodes > self.config.analysis.graph_nodes_max {
            self.stop_analysis("Shell syntax tree exceeds the analysis limit");
            return;
        }
        match node.kind() {
            "comment" | "heredoc_body" | "heredoc_start" | "heredoc_end" => {}
            "command" | "variable_assignment" => self.shell_command(node, source, depth, None),
            "redirected_statement" => {
                let body = node.child_by_field_name("body");
                let mut input = None;
                for child in children(node) {
                    match child.kind() {
                        "heredoc_redirect" => {
                            let descriptor = child
                                .child_by_field_name("descriptor")
                                .map(|n| text(n, source));
                            let start = children(child)
                                .into_iter()
                                .find(|n| n.kind() == "heredoc_start");
                            let body = children(child)
                                .into_iter()
                                .find(|n| n.kind() == "heredoc_body");
                            if let (Some(start), Some(body)) = (start, body) {
                                let delimiter = text(start, source);
                                let quoted = delimiter.contains(['\'', '"', '\\']);
                                let raw = text(body, source);
                                // Expansion nodes belong to the outer shell, even if stdin is data.
                                if !quoted {
                                    self.heredoc_expansions(body, source, depth, ast_depth + 1);
                                }
                                if descriptor.is_none_or(|fd| fd == "0") {
                                    input = Some(ShellInput {
                                        text: raw.to_owned(),
                                        dynamic: !quoted && raw.contains(['$', '`', '\\']),
                                    });
                                }
                            } else {
                                self.syntax_partial = true;
                                self.unknown("Heredoc body is unavailable");
                            }
                            // The grammar can attach a command following &&/|| to the redirect.
                            if let Some(right) = child.child_by_field_name("right") {
                                self.syntax_partial = true;
                                self.unknown("Commands attached to a heredoc have partial control-flow coverage");
                                self.walk_shell(right, source, depth, ast_depth + 1);
                            }
                        }
                        "file_redirect" | "herestring_redirect" => {
                            self.shell_redirect(child, source, depth);
                            let raw = text(child, source);
                            if raw.contains('<') {
                                input = None;
                            }
                        }
                        _ => {}
                    }
                }
                if let Some(body) = body {
                    if body.kind() == "command" {
                        self.shell_command(body, source, depth, input.as_ref());
                    } else {
                        if input.is_some() {
                            self.syntax_partial = true;
                            self.unknown("Heredoc consumer is compound or unresolved");
                        }
                        self.walk_shell(body, source, depth, ast_depth + 1);
                    }
                }
            }
            "pipeline" => {
                let cwd = self.cwd.clone();
                let stages = children(node);
                let mut remote_stream = false;
                for stage in stages {
                    self.cwd = cwd.clone();
                    // The effective command is resolved by the same wrapper logic used for effects.
                    let previous = self.remote_stream;
                    self.remote_stream = remote_stream;
                    self.last_network_producer = false;
                    self.walk_shell(stage, source, depth, ast_depth + 1);
                    remote_stream |= self.last_network_producer;
                    self.stream_secret |= self.read_secret;
                    self.read_secret = false;
                    self.remote_stream = previous;
                    self.print_outputs.clear();
                }
                self.cwd = cwd;
                self.stream_secret = false;
            }
            "program" | "list" => {
                let mut previous_end = node.start_byte();
                for child in children(node) {
                    let separator = &source[previous_end..child.start_byte()];
                    if !separator.contains("&&") {
                        self.print_outputs.clear();
                    }
                    if separator.contains("||") {
                        self.cwd = None;
                        self.context_partial = true;
                        self.unknown(
                            "Conditional failure path has an unresolved working directory",
                        );
                    }
                    if separator.contains('&') && !separator.contains("&&") {
                        self.syntax_partial = true;
                        self.unknown("Background execution has partial coverage");
                    }
                    self.walk_shell(child, source, depth, ast_depth + 1);
                    previous_end = child.end_byte();
                }
                if source[previous_end..node.end_byte()].contains('&') {
                    self.syntax_partial = true;
                    self.unknown("Background execution has partial coverage");
                }
            }
            "subshell" => {
                let cwd = self.cwd.clone();
                for child in children(node) {
                    self.walk_shell(child, source, depth, ast_depth + 1);
                }
                self.cwd = cwd;
                self.print_outputs.clear();
            }
            _ => {
                self.syntax_partial = true;
                self.unknown(&format!("Unsupported shell construct: {}", node.kind()));
                // Keep known hazardous findings in recoverable subtrees.
                let cwd = self.cwd.clone();
                for child in children(node) {
                    self.walk_shell(child, source, depth, ast_depth + 1);
                }
                self.cwd = cwd;
                self.print_outputs.clear();
            }
        }
    }

    fn heredoc_expansions(&mut self, node: Node<'_>, source: &str, depth: usize, ast_depth: usize) {
        if !self.within_budget() || ast_depth > 64 {
            return;
        }
        for child in children(node) {
            if child.kind() == "command_substitution" {
                for nested in children(child) {
                    self.walk_shell(nested, source, depth + 1, ast_depth + 1);
                }
            } else {
                self.heredoc_expansions(child, source, depth, ast_depth + 1);
            }
        }
    }

    fn shell_command(
        &mut self,
        node: Node<'_>,
        source: &str,
        depth: usize,
        input: Option<&ShellInput>,
    ) {
        // Decode the entire command after masking AST-owned redirects. Decoding
        // separate argument nodes would split a word joined by a line continuation.
        let mut raw = text(node, source).as_bytes().to_vec();
        for child in children(node) {
            if matches!(child.kind(), "file_redirect" | "herestring_redirect") {
                self.shell_redirect(child, source, depth);
                raw[child.start_byte() - node.start_byte()..child.end_byte() - node.start_byte()]
                    .fill(b' ');
            } else {
                self.process_substitutions(child, source, depth, 0);
            }
        }
        let decoded =
            String::from_utf8(raw).expect("masking complete syntax nodes preserves UTF-8");
        let tokens = match lex(&decoded) {
            Ok(tokens) => tokens,
            Err(error) => {
                self.syntax_partial = true;
                self.unknown(&error);
                return;
            }
        };
        if tokens.iter().any(|token| matches!(token, Token::Op(_))) {
            self.syntax_partial = true;
            self.unknown("Shell word requires unsupported expansion semantics");
        }
        let previous = self.shell_location.replace(distill_core::SourceLocation {
            file: None,
            line: node.start_position().row + 1,
            column: node.start_position().column + 1,
        });
        self.analyze_segment(&tokens, depth, input);
        self.shell_location = previous;
    }

    fn process_substitutions(
        &mut self,
        node: Node<'_>,
        source: &str,
        depth: usize,
        ast_depth: usize,
    ) {
        if !self.within_budget() || ast_depth > 64 {
            return;
        }
        if node.kind() == "process_substitution" {
            let cwd = self.cwd.clone();
            for child in children(node) {
                self.walk_shell(child, source, depth + 1, ast_depth + 1);
            }
            self.cwd = cwd;
        } else if node.kind() != "command_substitution" {
            for child in children(node) {
                self.process_substitutions(child, source, depth, ast_depth + 1);
            }
        }
    }

    fn shell_redirect(&mut self, node: Node<'_>, source: &str, depth: usize) {
        if !self.within_budget() {
            return;
        }
        if node.kind() == "herestring_redirect" {
            self.syntax_partial = true;
            self.unknown("Here-string input has partial coverage");
        }
        if let Some(destination) = node.child_by_field_name("destination") {
            match lex(text(destination, source)) {
                Ok(tokens) => {
                    for token in tokens {
                        if let Token::Word(word) = token {
                            for nested in &word.substitutions {
                                self.analyze(nested, depth + 1);
                            }
                            let prefix = &source[node.start_byte()..destination.start_byte()];
                            let op = if prefix.contains(">>") {
                                ">>"
                            } else if prefix.contains(">&") || prefix.contains("<&") {
                                "dup"
                            } else if prefix.contains('>') {
                                ">"
                            } else {
                                "<"
                            };
                            if op != "dup"
                                || !word.text.chars().all(|c| c.is_ascii_digit() || c == '-')
                            {
                                self.redirect(op, &word);
                            }
                        }
                    }
                }
                Err(error) => {
                    self.syntax_partial = true;
                    self.unknown(&error);
                }
            }
        } else {
            self.syntax_partial = true;
            self.unknown("Redirection target is unavailable");
        }
    }

    pub(super) fn inspect_stdin(
        &mut self,
        name: &str,
        args: &[Word],
        input: Option<&ShellInput>,
        depth: usize,
    ) -> bool {
        let Some(input) = input else {
            return false;
        };
        let stdin_code = match name {
            "sh" | "bash" | "zsh" => {
                args.is_empty()
                    || args
                        .iter()
                        .all(|arg| matches!(arg.text.as_str(), "-s" | "--"))
            }
            name if crate::is_python(name) => {
                args.is_empty() || matches!(args, [arg] if arg.text == "-")
            }
            "node" => args.is_empty() || matches!(args, [arg] if arg.text == "-"),
            _ => false,
        };
        if !stdin_code {
            return false;
        }
        if input.dynamic {
            self.syntax_partial = true;
            self.unresolved_program("Interpreter input contains unresolved shell expansions");
        } else {
            match name {
                "sh" | "bash" | "zsh" => self.analyze(&input.text, depth + 1),
                "node" => {
                    self.inspect_program(Language::JavaScript, &input.text, None);
                }
                _ => {
                    self.inspect_program(Language::Python, &input.text, None);
                }
            }
        }
        true
    }

    pub(super) fn check_stream_consumer(&mut self, name: &str, args: &[Word]) {
        self.last_network_producer = matches!(name, "curl" | "wget" | "nc");
        let consumes_code = match name {
            "sh" | "bash" | "zsh" => {
                args.is_empty() || args.iter().all(|a| matches!(a.text.as_str(), "-s" | "--"))
            }
            name if crate::is_python(name) => {
                args.is_empty() || matches!(args, [arg] if arg.text == "-")
            }
            "node" => args.is_empty() || matches!(args, [arg] if arg.text == "-"),
            _ => false,
        };
        if self.remote_stream && consumes_code {
            self.finding(
                Severity::Critical,
                EffectKind::Execute,
                "exec.downloaded-to-shell",
                "Downloaded content is piped to an interpreter",
            );
            self.opaque = true;
            self.context_partial = true;
            self.unknown("Downloaded script contents are unavailable before execution");
        }
    }
}

fn children(node: Node<'_>) -> Vec<Node<'_>> {
    let mut cursor = node.walk();
    node.named_children(&mut cursor).collect()
}

fn text<'a>(node: Node<'_>, source: &'a str) -> &'a str {
    &source[node.byte_range()]
}

#[cfg(test)]
mod tests;
