//! Read-only Git index v2/v3 inspection. Never invokes Git, hooks, filters, or fsmonitor.
use sha1::{Digest, Sha1};
use std::path::Path;
pub fn tracked_clean(path: &Path) -> Option<bool> {
    let root = path
        .ancestors()
        .find(|directory| directory.join(".git/index").is_file())?;
    let relative = path.strip_prefix(root).ok()?.to_str()?;
    let budget = crate::AnalysisBudget::new(50);
    let (source, _) = crate::read_snapshot(path, &budget, 64 * 1024).ok()?;
    let index = std::fs::File::open(root.join(".git/index")).ok()?;
    use std::io::Read;
    if index.metadata().ok()?.len() > 1024 * 1024 {
        return None;
    }
    let mut bytes = Vec::new();
    index.take(1024 * 1024 + 1).read_to_end(&mut bytes).ok()?;
    if bytes.get(..4)? != b"DIRC" {
        return None;
    }
    let number = |offset| {
        bytes
            .get(offset..offset + 4)
            .and_then(|v| <[u8; 4]>::try_from(v).ok())
            .map(u32::from_be_bytes)
    };
    if !matches!(number(4)?, 2 | 3) {
        return None;
    }
    let count = number(8)? as usize;
    if count > 10000 {
        return None;
    }
    let mut cursor = 12;
    for _ in 0..count {
        if budget.expired() {
            return None;
        }
        let entry = bytes.get(cursor..)?;
        let oid = entry.get(40..60)?;
        let flags = u16::from_be_bytes(entry.get(60..62)?.try_into().ok()?);
        let start = if flags & 0x4000 != 0 { 64 } else { 62 };
        let end = start + entry.get(start..)?.iter().position(|byte| *byte == 0)?;
        let name = std::str::from_utf8(entry.get(start..end)?).ok()?;
        if name == relative {
            if flags & 0x3000 != 0 {
                return None;
            }
            let mut digest = Sha1::new();
            digest.update(format!("blob {}\0", source.len()).as_bytes());
            digest.update(source.as_bytes());
            return Some(digest.finalize().as_slice() == oid);
        }
        cursor += (end + 1 + 7) & !7;
    }
    Some(false)
}
