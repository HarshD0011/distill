#[derive(Clone, Debug)]
pub struct Word {
    pub text: String,
    pub dynamic: bool,
    /// Only an unquoted leading tilde has shell expansion semantics.
    pub tilde_expansion: bool,
    pub substitutions: Vec<String>,
}

#[derive(Clone, Debug)]
pub enum Token {
    Word(Word),
    Op(String),
}

/// Normalize literal quoting and whitespace for retry correlation only.
/// Different operands/program text must not collapse into a shared uncertainty class.
pub fn retry_fingerprint(input: &str) -> String {
    let normalized = lex(input)
        .map(|tokens| format!("{tokens:?}"))
        .unwrap_or_else(|_| input.into());
    distill_core::sha256(normalized.as_bytes())
}

pub fn lex(input: &str) -> Result<Vec<Token>, String> {
    let chars: Vec<char> = input.chars().collect();
    let mut tokens = Vec::new();
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if c == ' ' || c == '\t' {
            i += 1;
            continue;
        }
        if c == '#' {
            while i < chars.len() && chars[i] != '\n' {
                i += 1;
            }
            continue;
        }
        if is_op(c) {
            let mut op = c.to_string();
            if i + 1 < chars.len()
                && ((c == '&' && chars[i + 1] == '&')
                    || (c == '|' && chars[i + 1] == '|')
                    || (c == '>' && chars[i + 1] == '>')
                    || (c == '<' && chars[i + 1] == '<'))
            {
                op.push(chars[i + 1]);
                i += 1;
            }
            tokens.push(Token::Op(op));
            i += 1;
            continue;
        }
        let mut word = Word {
            text: String::new(),
            dynamic: false,
            tilde_expansion: chars[i] == '~',
            substitutions: Vec::new(),
        };
        // Shell syntax blanks are space/tab, not Rust's larger Unicode whitespace set.
        // Keep this predicate identical to the outer skip, so every iteration advances.
        while i < chars.len() && !matches!(chars[i], ' ' | '\t') && !is_op(chars[i]) {
            match chars[i] {
                '\'' => {
                    i += 1;
                    while i < chars.len() && chars[i] != '\'' {
                        word.text.push(chars[i]);
                        i += 1;
                    }
                    if i == chars.len() {
                        return Err("Unclosed single quote".into());
                    }
                    i += 1;
                }
                '"' => {
                    i += 1;
                    while i < chars.len() && chars[i] != '"' {
                        if chars[i] == '$' {
                            consume_dollar(&chars, &mut i, &mut word)?;
                        } else if chars[i] == '`' {
                            consume_backticks(&chars, &mut i, &mut word)?;
                        } else if chars[i] == '\\' && i + 1 < chars.len() {
                            if matches!(chars[i + 1], '$' | '`' | '"' | '\\' | '\n') {
                                i += 1;
                                if chars[i] != '\n' {
                                    word.text.push(chars[i]);
                                }
                                i += 1;
                            } else {
                                word.text.push('\\');
                                i += 1;
                            }
                        } else {
                            word.text.push(chars[i]);
                            i += 1;
                        }
                    }
                    if i == chars.len() {
                        return Err("Unclosed double quote".into());
                    }
                    i += 1;
                }
                '$' => consume_dollar(&chars, &mut i, &mut word)?,
                '`' => consume_backticks(&chars, &mut i, &mut word)?,
                '\\' if i + 1 < chars.len() => {
                    i += 1;
                    if chars[i] != '\n' {
                        word.text.push(chars[i]);
                    }
                    i += 1;
                }
                other => {
                    // Braces are ordinary word characters unless an unquoted
                    // comma/range activates brace expansion. Structural brace
                    // groups are handled by the shell AST, not this word lexer.
                    if other == '{'
                        && let Some(end) = chars[i + 1..].iter().position(|c| *c == '}')
                    {
                        let body = &chars[i + 1..i + 1 + end];
                        if body.contains(&',') || body.windows(2).any(|pair| pair == ['.', '.']) {
                            word.dynamic = true;
                        }
                    }
                    word.text.push(other);
                    i += 1;
                }
            }
        }
        tokens.push(Token::Word(word));
    }
    Ok(tokens)
}

fn consume_dollar(chars: &[char], i: &mut usize, word: &mut Word) -> Result<(), String> {
    if chars.get(*i + 1) == Some(&'(') {
        let start = *i + 2;
        let mut depth = 1;
        let mut j = start;
        let mut quote = None;
        while j < chars.len() {
            let c = chars[j];
            if c == '\\' {
                j += 2;
                continue;
            }
            if let Some(q) = quote {
                if c == q {
                    quote = None;
                }
            } else if c == '\'' || c == '"' {
                quote = Some(c);
            } else if c == '(' {
                depth += 1;
            } else if c == ')' {
                depth -= 1;
                if depth == 0 {
                    break;
                }
            }
            j += 1;
        }
        if depth != 0 {
            return Err("Unclosed command substitution".into());
        }
        word.substitutions.push(chars[start..j].iter().collect());
        word.dynamic = true;
        word.text.push_str("$(");
        word.text.push_str("...");
        word.text.push(')');
        *i = j + 1;
    } else {
        word.dynamic = true;
        word.text.push('$');
        *i += 1;
    }
    Ok(())
}

fn consume_backticks(chars: &[char], i: &mut usize, word: &mut Word) -> Result<(), String> {
    let start = *i + 1;
    let mut end = start;
    while end < chars.len() {
        if chars[end] == '\\' {
            end += 2;
            continue;
        }
        if chars[end] == '`' {
            break;
        }
        end += 1;
    }
    if end >= chars.len() {
        return Err("Unclosed backtick substitution".into());
    }
    word.substitutions.push(chars[start..end].iter().collect());
    word.dynamic = true;
    word.text.push_str("`...`");
    *i = end + 1;
    Ok(())
}

fn is_op(c: char) -> bool {
    matches!(c, ';' | '\n' | '|' | '&' | '>' | '<' | '(' | ')')
}

pub fn is_assignment(word: &Word) -> bool {
    word.text.split_once('=').is_some_and(|(name, _)| {
        !name.is_empty() && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
    })
}

pub fn command_name(tokens: &[Token]) -> Option<String> {
    tokens.iter().find_map(|t| match t {
        Token::Word(w) if !is_assignment(w) => {
            Some(w.text.rsplit('/').next().unwrap_or(&w.text).to_string())
        }
        _ => None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn comments_are_not_commands() {
        let tokens = lex("echo 'rm -rf /' # rm -rf /").unwrap();
        assert!(matches!(&tokens[0], Token::Word(w) if w.text == "echo"));
        assert!(matches!(&tokens[1], Token::Word(w) if w.text == "rm -rf /"));
        assert_eq!(tokens.len(), 2);
    }

    #[test]
    fn non_shell_whitespace_is_literal_and_always_advances() {
        for whitespace in [
            '\u{b}', '\u{c}', '\r', '\u{85}', '\u{a0}', '\u{2028}', '\u{2029}',
        ] {
            let source = format!("one{whitespace}two");
            let tokens = super::lex(&source).unwrap();
            assert_eq!(tokens.len(), 1);
            assert!(matches!(&tokens[0], super::Token::Word(word) if word.text == source));
        }
        assert!(super::lex("\u{3}\u{b}@\n").unwrap().len() < 5);
    }

    #[test]
    fn substitution_is_nested_text() {
        let tokens = lex("echo $(rm -rf /)").unwrap();
        let Token::Word(word) = &tokens[1] else {
            panic!("expected word");
        };
        assert!(word.dynamic);
        assert_eq!(word.substitutions, vec!["rm -rf /"]);
    }

    #[test]
    fn quoting_preserves_literal_paths_and_backslashes() {
        let tokens = lex("node ~/a.js '~/b.js' \"~/c.js\" \\~/d.js \"a\\b.js\"").unwrap();
        let words: Vec<_> = tokens
            .iter()
            .filter_map(|token| match token {
                Token::Word(word) => Some(word),
                _ => None,
            })
            .collect();
        assert!(words[1].tilde_expansion);
        assert!(words[2..].iter().all(|word| !word.tilde_expansion));
        assert_eq!(words[5].text, "a\\b.js");
        let tokens = lex("no\\\nde -e \"console.log(\\\n1)\"").unwrap();
        assert!(matches!(&tokens[0], Token::Word(word) if word.text == "node"));
        assert!(matches!(&tokens[2], Token::Word(word) if word.text == "console.log(1)"));
    }

    #[cfg(unix)]
    #[test]
    fn literal_word_decoding_agrees_with_real_bash_and_zsh() {
        // Only generated printf literals run. No command substitutions, expansions, or external inputs.
        for shell in ["/bin/bash", "/bin/zsh"] {
            if !std::path::Path::new(shell).is_file() {
                continue;
            }
            for index in 0..100 {
                let values = [
                    format!("literal-{index}"),
                    "a b".into(),
                    "a'b\"c".into(),
                    "literal $IFS and `text`".into(),
                    "line\none".into(),
                ];
                let words = values
                    .iter()
                    .map(|value| format!("'{}'", value.replace('\'', "'\"'\"'")))
                    .collect::<Vec<_>>()
                    .join(" ");
                let source = format!("printf '%s\\0' {words}");
                let parsed = super::lex(&source)
                    .unwrap()
                    .into_iter()
                    .filter_map(|token| match token {
                        super::Token::Word(word) => Some(word.text),
                        _ => None,
                    })
                    .skip(2)
                    .collect::<Vec<_>>();
                let mut command = std::process::Command::new(shell);
                command.env_clear().env("PATH", "/usr/bin:/bin");
                if shell.ends_with("zsh") {
                    command.args(["-f", "-d"]);
                } else {
                    command.args(["--noprofile", "--norc"]);
                }
                let output = command.args(["-c", &source]).output().unwrap();
                assert!(output.status.success());
                let actual = output
                    .stdout
                    .split(|byte| *byte == 0)
                    .filter(|value| !value.is_empty())
                    .map(|value| String::from_utf8(value.to_vec()).unwrap())
                    .collect::<Vec<_>>();
                assert_eq!(parsed, actual, "{shell}: {source}");
            }
        }
    }
}

#[cfg(test)]
mod brace_regressions {
    #[test]
    fn literal_braces_remain_one_word_and_expansions_remain_dynamic() {
        for source in ["-I{}", "prefix{}suffix", "{literal}"] {
            let tokens = super::lex(source).unwrap();
            assert!(
                matches!(tokens.as_slice(), [super::Token::Word(word)] if word.text == source && !word.dynamic)
            );
        }
        for source in ["/{,tmp}", "file{1..3}"] {
            let tokens = super::lex(source).unwrap();
            assert!(matches!(tokens.as_slice(), [super::Token::Word(word)] if word.dynamic));
        }
        for source in ["'{a,b}'", "\"{1..3}\""] {
            assert!(
                matches!(super::lex(source).unwrap().as_slice(), [super::Token::Word(word)] if !word.dynamic)
            );
        }
    }
}
