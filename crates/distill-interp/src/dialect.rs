//! Zsh-specific guards around the shared structural subset.
use crate::Analyzer;
use distill_core::{EffectKind, Severity};
impl Analyzer<'_> {
    pub(super) fn inspect_zsh(&mut self, source: &str) {
        let compatible = self.shell_options.as_ref().is_some_and(|options| {
            let normalized = options
                .iter()
                .map(|option| option.to_ascii_lowercase().replace('_', ""))
                .collect::<Vec<_>>();
            [
                "noaliases",
                "norcs",
                "noglobalrcs",
                "noequals",
                "nomultios",
                "nobanghist",
                "noextendedglob",
                "noglobsubst",
                "noshwordsplit",
            ]
            .iter()
            .all(|required| normalized.iter().any(|option| option == required))
                && options.iter().all(|option| {
                    matches!(
                        option.to_ascii_lowercase().replace('_', "").as_str(),
                        "noglob"
                            | "noaliases"
                            | "norcs"
                            | "noglobalrcs"
                            | "noequals"
                            | "nomultios"
                            | "nobanghist"
                            | "noextendedglob"
                            | "noglobsubst"
                            | "noshwordsplit"
                            | "posixbuiltins"
                            | "interactivecomments"
                    )
                })
        });
        if !compatible {
            self.syntax_partial = true;
            self.raise(Severity::High);
            self.unknown("Zsh options are absent or outside the supported dialect snapshot");
        }
        if source.contains("(#q")
            || source.contains("(e:")
            || source.contains("(e'")
            || source.contains("(e\"")
            || source.contains("zsh/zpty")
            || source.contains("zsh/files")
            || source.contains("${~")
            || source.contains("${=")
        {
            self.finding(
                Severity::High,
                EffectKind::Execute,
                "exec.zsh-expansion",
                "Zsh expansion, glob qualifier, or module may execute code",
            );
            self.syntax_partial = true;
            self.unknown("Zsh executable expansion is unresolved");
        }
        if source
            .split_whitespace()
            .any(|word| word.starts_with('=') && word.len() > 1)
        {
            self.context_partial = true;
            self.raise(Severity::High);
            self.unknown("Zsh equals expansion depends on executable lookup");
        }
    }
}
