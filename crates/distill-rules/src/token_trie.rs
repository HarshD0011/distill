/// Token trie for flags, argument classes, and rule priority.
/// A 0xFF byte separates tokens so `rm` + `-r` cannot collide with `rm-r`.
const TOKEN_SEP: u8 = 0xFF;

struct TokenNode {
    edges: Vec<(u8, u32)>,
    rule: u16,
}

pub struct TokenTrie {
    nodes: Vec<TokenNode>,
}

impl TokenTrie {
    pub fn new() -> Self {
        Self {
            nodes: vec![TokenNode {
                edges: Vec::new(),
                rule: 0,
            }],
        }
    }

    pub fn insert(&mut self, tokens: &[&str], rule: u16) {
        let mut index = 0usize;
        for (offset, token) in tokens.iter().enumerate() {
            if offset > 0 {
                index = self.ensure_edge(index, TOKEN_SEP);
            }
            for byte in token.bytes() {
                index = self.ensure_edge(index, byte);
            }
        }
        self.nodes[index].rule = rule;
    }

    pub fn recognizes(&self, prefix: &[&str], token: &str) -> bool {
        let Some(mut index) = self.walk(prefix) else {
            return false;
        };
        if !prefix.is_empty() {
            let Some(next) = self.step(index, TOKEN_SEP) else {
                return false;
            };
            index = next;
        }
        for byte in token.bytes() {
            let Some(next) = self.step(index, byte) else {
                return false;
            };
            index = next;
        }
        true
    }

    /// Rule ids on tokens that were present. A missing later token keeps the prefix rules.
    pub fn collect(&self, tokens: &[&str]) -> Vec<u16> {
        let mut index = 0usize;
        let mut found = Vec::new();
        for (offset, token) in tokens.iter().enumerate() {
            if offset > 0 {
                let Some(next) = self.step(index, TOKEN_SEP) else {
                    break;
                };
                index = next;
            }
            let mut matched = true;
            for byte in token.bytes() {
                if let Some(next) = self.step(index, byte) {
                    index = next;
                } else {
                    matched = false;
                    break;
                }
            }
            if !matched {
                break;
            }
            if self.nodes[index].rule != 0 {
                found.push(self.nodes[index].rule);
            }
        }
        found
    }

    fn walk(&self, tokens: &[&str]) -> Option<usize> {
        let mut index = 0usize;
        for (offset, token) in tokens.iter().enumerate() {
            if offset > 0 {
                index = self.step(index, TOKEN_SEP)?;
            }
            for byte in token.bytes() {
                index = self.step(index, byte)?;
            }
        }
        Some(index)
    }

    fn step(&self, index: usize, byte: u8) -> Option<usize> {
        self.nodes[index]
            .edges
            .binary_search_by_key(&byte, |edge| edge.0)
            .ok()
            .map(|slot| self.nodes[index].edges[slot].1 as usize)
    }

    fn ensure_edge(&mut self, index: usize, byte: u8) -> usize {
        if let Some(child) = self.step(index, byte) {
            return child;
        }
        let child = self.nodes.len() as u32;
        self.nodes.push(TokenNode {
            edges: Vec::new(),
            rule: 0,
        });
        let edges = &mut self.nodes[index].edges;
        let slot = edges.partition_point(|edge| edge.0 < byte);
        edges.insert(slot, (byte, child));
        child as usize
    }
}
