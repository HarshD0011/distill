use crate::Analyzer;

impl Analyzer<'_> {
    pub(super) fn emit_path(&mut self, tokens: &[&str]) {
        for fired in distill_rules::catalog::considers(tokens) {
            if let Some(effect) = fired.effect {
                self.finding_with_basis(
                    fired.severity,
                    effect,
                    fired.id,
                    fired.impact,
                    fired.basis,
                );
            } else {
                self.raise(fired.severity);
            }
            if fired.partial {
                self.context_partial = true;
            }
            if let Some(unknown) = fired.unknown {
                self.unknown(unknown);
            }
        }
    }

    pub(super) fn flag_known(&self, prefix: &[&str], token: &str) -> bool {
        distill_rules::catalog::recognizes(prefix, token)
    }
}
