//! Bounded syntax-based analysis. Parsing never imports or executes candidate code.

use std::{collections::HashSet, ops::ControlFlow};

use tree_sitter::{Language as Grammar, Node, ParseOptions, Parser, Tree};

mod dynamic;
mod flow;
mod native;
mod operations;

pub(super) use operations::Observation;

pub(super) struct Analysis {
    pub print_only: bool,
    pub observations: Vec<Observation>,
}

#[derive(Clone, Copy, Debug)]
pub(super) enum Language {
    Python,
    JavaScript,
    Go,
    C,
    Cpp,
    Rust,
}

impl Language {
    fn grammar(self) -> Grammar {
        match self {
            Self::Python => tree_sitter_python::LANGUAGE.into(),
            Self::JavaScript => tree_sitter_javascript::LANGUAGE.into(),
            Self::Go => tree_sitter_go::LANGUAGE.into(),
            Self::C => tree_sitter_c::LANGUAGE.into(),
            Self::Cpp => tree_sitter_cpp::LANGUAGE.into(),
            Self::Rust => tree_sitter_rust::LANGUAGE.into(),
        }
    }
}

fn parse(language: Language, source: &str, budget: &distill_core::AnalysisBudget) -> Option<Tree> {
    if source.len() > 64 * 1024 {
        return None;
    }
    let mut parser = Parser::new();
    parser.set_language(&language.grammar()).ok()?;
    let mut progress = |_: &tree_sitter::ParseState| {
        if budget.expired() {
            ControlFlow::Break(())
        } else {
            ControlFlow::Continue(())
        }
    };
    parser.parse_with_options(
        &mut |offset, _| source.as_bytes().get(offset..).unwrap_or_default(),
        None,
        Some(ParseOptions::new().progress_callback(&mut progress)),
    )
}

#[cfg(test)]
pub(super) fn analyze(language: Language, source: &str) -> Result<Analysis, &'static str> {
    analyze_with_budget(language, source, &distill_core::AnalysisBudget::new(100))
}

pub(super) fn analyze_with_budget(
    language: Language,
    source: &str,
    budget: &distill_core::AnalysisBudget,
) -> Result<Analysis, &'static str> {
    if budget.expired() {
        return Err("Shared analysis deadline exhausted");
    }
    let tree =
        parse(language, source, budget).ok_or("Source size or parsing time limit reached")?;
    let root = tree.root_node();
    if root.has_error() {
        return Err("Source contains syntax errors or missing syntax");
    }
    // Bound both the semantic walk and its recursive helper functions.
    let mut stack = vec![(root, 0)];
    let mut nodes = 0;
    while let Some((node, depth)) = stack.pop() {
        if !budget.visit_node() {
            return Err(budget.stop_reason());
        }
        if budget.expired() {
            return Err("Shared analysis deadline exhausted");
        }
        nodes += 1;
        if nodes > 4096 || depth > 64 {
            return Err("Source syntax tree exceeds the analysis limit");
        }
        stack.extend(children(node).into_iter().map(|child| (child, depth + 1)));
    }
    let print_only = match language {
        Language::Python | Language::JavaScript => dynamic::print_only(language, root, source),
        _ => native::print_only(language, root, source),
    };
    Ok(Analysis {
        print_only,
        observations: if print_only {
            Vec::new()
        } else {
            operations::collect(language, root, source)
        },
    })
}

fn children(node: Node<'_>) -> Vec<Node<'_>> {
    let mut cursor = node.walk();
    node.named_children(&mut cursor)
        .filter(|child| !matches!(child.kind(), "comment" | "line_comment" | "block_comment"))
        .collect()
}

fn text<'a>(node: Node<'_>, source: &'a str) -> &'a str {
    node.utf8_text(source.as_bytes()).unwrap_or("")
}

fn field_text<'a>(node: Node<'_>, name: &str, source: &'a str) -> Option<&'a str> {
    node.child_by_field_name(name)
        .map(|child| text(child, source))
}

fn literal(node: Node<'_>, _source: &str) -> bool {
    match node.kind() {
        "integer" | "float" | "number" | "true" | "false" | "none" | "null" | "int_literal"
        | "float_literal" | "imaginary_literal" | "rune_literal" | "number_literal"
        | "char_literal" | "integer_literal" | "boolean_literal" => true,
        "string" | "string_literal" | "raw_string_literal" | "interpreted_string_literal" => {
            // Formatting/interpolation nodes contain expressions, not literal data.
            !children(node)
                .iter()
                .any(|child| matches!(child.kind(), "interpolation" | "template_substitution"))
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests;

fn pure(node: Node<'_>, source: &str, symbols: &HashSet<String>) -> bool {
    if literal(node, source) {
        return true;
    }
    match node.kind() {
        "identifier" => symbols.contains(text(node, source)),
        "parenthesized_expression" => {
            let items = children(node);
            items.len() == 1 && pure(items[0], source, symbols)
        }
        "unary_operator" | "unary_expression" => {
            matches!(
                field_text(node, "operator", source),
                Some("+" | "-" | "!" | "~" | "not")
            ) && node
                .child_by_field_name("argument")
                .or_else(|| children(node).last().copied())
                .is_some_and(|arg| pure(arg, source, symbols))
        }
        "binary_operator" | "binary_expression" => {
            matches!(
                field_text(node, "operator", source),
                Some("+" | "-" | "*" | "/" | "//" | "%")
            ) && node
                .child_by_field_name("left")
                .is_some_and(|arg| pure(arg, source, symbols))
                && node
                    .child_by_field_name("right")
                    .is_some_and(|arg| pure(arg, source, symbols))
        }
        _ => false,
    }
}
