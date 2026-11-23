//! EDE blobs stored in per-slice arenas.

pub fn encode_edes(edes: &[(u16, &str)]) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.push(edes.len().min(255) as u8);
    for (code, text) in edes.iter().take(255) {
        buf.extend_from_slice(&code.to_be_bytes());
        let bytes = text.as_bytes();
        let len = bytes.len().min(u16::MAX as usize) as u16;
        buf.extend_from_slice(&len.to_be_bytes());
        buf.extend_from_slice(&bytes[..len as usize]);
    }
    buf
}

pub fn ede_entries(blob: &[u8]) -> Vec<(u16, String)> {
    if blob.is_empty() {
        return Vec::new();
    }
    let count = blob[0] as usize;
    let mut out = Vec::with_capacity(count);
    let mut pos = 1usize;
    for _ in 0..count {
        if pos + 4 > blob.len() {
            break;
        }
        let code = u16::from_be_bytes([blob[pos], blob[pos + 1]]);
        pos += 2;
        let len = u16::from_be_bytes([blob[pos], blob[pos + 1]]) as usize;
        pos += 2;
        if pos + len > blob.len() {
            break;
        }
        let text = String::from_utf8_lossy(&blob[pos..pos + len]).into_owned();
        pos += len;
        out.push((code, text));
    }
    out
}

pub fn distinct_ede_codes(blob: &[u8]) -> Vec<u16> {
    let mut codes: Vec<u16> = ede_entries(blob).into_iter().map(|(c, _)| c).collect();
    codes.sort_unstable();
    codes.dedup();
    codes
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_edes() {
        let blob = encode_edes(&[(22, "a"), (23, "b")]);
        let entries = ede_entries(&blob);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].0, 22);
        assert_eq!(distinct_ede_codes(&blob), vec![22, 23]);
    }
}
