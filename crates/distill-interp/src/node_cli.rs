//! Bounded Node option grammar. Options after an eval still matter; script
//! arguments after the first operand or `--` are data, not interpreter options.
use distill_parse::Word;

#[derive(Debug)]
pub(super) enum Target {
    Code(Word),
    File(Word),
    Stdin,
    Info,
}

#[derive(Debug)]
pub(super) struct Invocation {
    pub target: Target,
    pub preloads: Vec<Word>,
    pub configuration: Vec<Word>,
    pub gaps: Vec<&'static str>,
    pub typescript: bool,
}

pub(super) fn parse(args: &[Word]) -> Result<Invocation, &'static str> {
    let mut result = Invocation {
        target: Target::Stdin,
        preloads: vec![],
        configuration: vec![],
        gaps: vec![],
        typescript: false,
    };
    if matches!(args, [arg] if !arg.dynamic && matches!(arg.text.as_str(), "--version" | "-v" | "--help" | "-h"))
    {
        result.target = Target::Info;
        return Ok(result);
    }
    let mut index = 0;
    let mut input_type = false;
    while let Some(word) = args.get(index) {
        index += 1;
        if word.dynamic {
            return Err("Node option or source selection is dynamic");
        }
        if word.text == "--" {
            if !matches!(result.target, Target::Code(_)) {
                result.target = operand(args.get(index));
            }
            break;
        }
        if word.text == "-" || !word.text.starts_with('-') {
            if !matches!(result.target, Target::Code(_)) {
                result.target = operand(Some(word));
            }
            break;
        }
        let (flag, attached) = if let Some(value) = word.text.strip_prefix("-e")
            && !word.text.starts_with("--")
            && !value.is_empty()
        {
            ("-e", Some(value))
        } else if let Some(value) = word.text.strip_prefix("-r")
            && !word.text.starts_with("--")
            && !value.is_empty()
        {
            ("-r", Some(value))
        } else {
            word.text
                .split_once('=')
                .map_or((word.text.as_str(), None), |(a, b)| (a, Some(b)))
        };
        match flag {
            "--no-warnings" | "--no-deprecation" if attached.is_none() => {}
            "--interactive" | "-i" if attached.is_none() => result
                .gaps
                .push("Node interactive mode can execute additional input"),
            "-e"
            | "--eval"
            | "--input-type"
            | "-r"
            | "--require"
            | "--import"
            | "--loader"
            | "--experimental-loader"
            | "--env-file"
            | "--env-file-if-exists"
            | "--config-file"
            | "--experimental-config-file" => {
                let value = if let Some(value) = attached {
                    let mut v = word.clone();
                    v.text = value.into();
                    v
                } else {
                    let v = args
                        .get(index)
                        .ok_or("Node option value is missing")?
                        .clone();
                    index += 1;
                    v
                };
                match flag {
                    "-e" | "--eval" => {
                        if matches!(result.target, Target::Code(_)) {
                            return Err("Repeated Node eval options are unresolved");
                        }
                        result.target = Target::Code(value);
                    }
                    "--input-type" => {
                        if value.dynamic
                            || !matches!(
                                value.text.as_str(),
                                "commonjs" | "module" | "commonjs-typescript" | "module-typescript"
                            )
                        {
                            return Err("Node input type is unsupported or dynamic");
                        }
                        input_type = true;
                        if value.text.ends_with("-typescript") {
                            result.typescript = true;
                            result.gaps.push("TypeScript runtime transformation and dependency behavior are unresolved");
                        }
                    }
                    "--env-file"
                    | "--env-file-if-exists"
                    | "--config-file"
                    | "--experimental-config-file" => result.configuration.push(value),
                    _ => result.preloads.push(value),
                }
            }
            _ => return Err("Node interpreter option is unsupported"),
        }
    }
    if input_type && matches!(result.target, Target::File(_)) {
        result
            .gaps
            .push("Node input type applies to eval or stdin, not a source file");
    }
    if matches!(&result.target, Target::File(v) if v.dynamic) {
        return Err("Node script path is dynamic");
    }
    Ok(result)
}

fn operand(word: Option<&Word>) -> Target {
    match word {
        None => Target::Stdin,
        Some(word) if word.text == "-" => Target::Stdin,
        Some(word) => Target::File(word.clone()),
    }
}

pub(super) fn stdin(args: &[Word]) -> bool {
    parse(args).is_ok_and(|invocation| matches!(invocation.target, Target::Stdin))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn args(source: &str) -> Vec<Word> {
        distill_parse::lex(source)
            .unwrap()
            .into_iter()
            .filter_map(|v| {
                if let distill_parse::Token::Word(w) = v {
                    Some(w)
                } else {
                    None
                }
            })
            .collect()
    }
    #[test]
    fn eval_does_not_hide_later_runtime_options() {
        let parsed = parse(&args(
            "-e 'console.log(1)' --require=./before.cjs --input-type commonjs",
        ))
        .unwrap();
        assert!(matches!(parsed.target, Target::Code(_)));
        assert_eq!(parsed.preloads[0].text, "./before.cjs");
    }
    #[test]
    fn application_arguments_do_not_become_preloads() {
        for source in [
            "app.mjs --require evil",
            "-- app.cjs --import evil",
            "-e 'console.log(1)' -- --require evil",
            "-e 'console.log(1)' data --require evil",
        ] {
            let parsed = parse(&args(source)).unwrap();
            assert!(parsed.preloads.is_empty(), "{source}");
        }
    }
    #[test]
    fn options_never_guess_unknown_arity_or_ignore_dynamic_sources() {
        for source in [
            "--mystery value -e 'console.log(1)'",
            "-e one -e two",
            "--input-type",
            "--require",
            "-- $SCRIPT",
        ] {
            assert!(parse(&args(source)).is_err(), "{source}");
        }
        assert!(matches!(
            parse(&args("--input-type=module -")).unwrap().target,
            Target::Stdin
        ));
        assert!(matches!(
            parse(&args("--eval=console.log(1)")).unwrap().target,
            Target::Code(_)
        ));
    }
}
