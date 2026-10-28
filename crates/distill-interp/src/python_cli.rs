//! Python's interpreter options end at -c, -m, a file, or stdin.
use distill_parse::Word;

pub(super) enum Target {
    Code(Word),
    Module(Word),
    File(Word),
    Stdin,
    Info,
}
pub(super) struct Invocation {
    pub target: Target,
    pub arguments: Vec<Word>,
    pub xoptions: Vec<Word>,
    pub woptions: Vec<Word>,
    pub interactive: bool,
}
pub(super) fn parse(args: &[Word]) -> Result<Invocation, &'static str> {
    let mut parsed = Invocation {
        target: Target::Stdin,
        arguments: vec![],
        xoptions: vec![],
        woptions: vec![],
        interactive: false,
    };
    let mut index = 0;
    while let Some(word) = args.get(index) {
        index += 1;
        if word.dynamic {
            return Err("Python interpreter option or source selection is dynamic");
        }
        if word.text == "--" {
            if let Some(file) = args.get(index) {
                parsed.target = if file.text == "-" {
                    Target::Stdin
                } else {
                    Target::File(file.clone())
                };
                parsed.arguments = args[index + 1..].to_vec();
            }
            return Ok(parsed);
        }
        if word.text == "-" || !word.text.starts_with('-') {
            parsed.target = if word.text == "-" {
                Target::Stdin
            } else {
                Target::File(word.clone())
            };
            parsed.arguments = args[index..].to_vec();
            return Ok(parsed);
        }
        if matches!(
            word.text.as_str(),
            "--version" | "--help" | "--help-env" | "--help-xoptions" | "--help-all"
        ) {
            parsed.target = Target::Info;
            return Ok(parsed);
        }
        if word.text == "--check-hash-based-pycs" {
            let value = args.get(index).ok_or("Python option value is missing")?;
            if value.dynamic || !matches!(value.text.as_str(), "default" | "always" | "never") {
                return Err("Python bytecode validation mode is unresolved");
            }
            index += 1;
            continue;
        }
        if word.text.starts_with("--") {
            return Err("Python interpreter option is unsupported");
        }
        for (offset, flag) in word.text[1..].char_indices() {
            if matches!(flag, 'c' | 'm' | 'W' | 'X') {
                let remainder = &word.text[offset + 2..];
                let value = if remainder.is_empty() {
                    let value = args
                        .get(index)
                        .ok_or("Python option value is missing")?
                        .clone();
                    index += 1;
                    value
                } else {
                    let mut value = word.clone();
                    value.text = remainder.into();
                    value
                };
                if matches!(flag, 'c' | 'm') {
                    parsed.target = if flag == 'c' {
                        Target::Code(value)
                    } else {
                        Target::Module(value)
                    };
                    parsed.arguments = args[index..].to_vec();
                    return Ok(parsed);
                }
                if flag == 'X' {
                    parsed.xoptions.push(value);
                } else {
                    parsed.woptions.push(value);
                }
                break;
            }
            match flag {
                'i' => parsed.interactive = true,
                'h' | '?' | 'V' => {
                    parsed.target = Target::Info;
                    return Ok(parsed);
                }
                'b' | 'B' | 'd' | 'E' | 'I' | 'O' | 'P' | 'q' | 'R' | 's' | 'S' | 'u' | 'v' => {}
                _ => return Err("Python interpreter option is unsupported"),
            }
        }
    }
    Ok(parsed)
}

pub(super) fn stdin(args: &[Word]) -> bool {
    parse(args).is_ok_and(|invocation| matches!(invocation.target, Target::Stdin))
}
