/// Static byte trie. Nodes and edges are generated into the binary, so a lookup
/// does not allocate or scan the full command list.

#[derive(Clone, Copy)]
pub struct Node {
    pub edge_start: u32,
    pub edge_count: u16,
    pub class: u8,
}

#[derive(Clone, Copy)]
pub struct Edge {
    pub byte: u8,
    pub child: u32,
}

pub fn lookup(nodes: &[Node], edges: &[Edge], key: &str) -> Option<u8> {
    if key.is_empty() || !key.is_ascii() {
        return None;
    }
    let mut index = 0usize;
    for byte in key.bytes() {
        let node = nodes[index];
        let start = node.edge_start as usize;
        let count = node.edge_count as usize;
        let slot = edges[start..start + count]
            .binary_search_by_key(&byte, |edge| edge.byte)
            .ok()?;
        index = edges[start + slot].child as usize;
    }
    let class = nodes[index].class;
    if class == 0 { None } else { Some(class) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefix_is_not_a_longer_key() {
        let nodes = &[
            Node {
                edge_start: 0,
                edge_count: 1,
                class: 0,
            },
            Node {
                edge_start: 1,
                edge_count: 1,
                class: 1,
            },
            Node {
                edge_start: 2,
                edge_count: 0,
                class: 2,
            },
        ];
        let edges = &[
            Edge {
                byte: b'r',
                child: 1,
            },
            Edge {
                byte: b'm',
                child: 2,
            },
        ];
        assert_eq!(lookup(nodes, edges, "r"), Some(1));
        assert_eq!(lookup(nodes, edges, "rm"), Some(2));
        assert_eq!(lookup(nodes, edges, "rmd"), None);
        assert_eq!(lookup(nodes, edges, ""), None);
    }
}
