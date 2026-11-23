use std::hash::Hash;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FlowKey {
    pub protocol: u8,
    pub a: [u8; 16],
    pub a_len: u8,
    pub a_port: u16,
    pub b: [u8; 16],
    pub b_len: u8,
    pub b_port: u16,
}

impl FlowKey {
    pub fn from_endpoints(
        protocol: u8,
        src_ip: &[u8],
        src_port: u16,
        dst_ip: &[u8],
        dst_port: u16,
    ) -> Self {
        let (a, a_len, a_port, b, b_len, b_port) =
            if endpoints_ordered(src_ip, src_port, dst_ip, dst_port) {
                (
                    pad_ip(src_ip),
                    src_ip.len() as u8,
                    src_port,
                    pad_ip(dst_ip),
                    dst_ip.len() as u8,
                    dst_port,
                )
            } else {
                (
                    pad_ip(dst_ip),
                    dst_ip.len() as u8,
                    dst_port,
                    pad_ip(src_ip),
                    src_ip.len() as u8,
                    src_port,
                )
            };
        Self {
            protocol,
            a,
            a_len,
            a_port,
            b,
            b_len,
            b_port,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FragmentKey {
    pub src: [u8; 16],
    pub src_len: u8,
    pub dst: [u8; 16],
    pub dst_len: u8,
    pub protocol: u8,
    pub ip_id: u32,
}

fn endpoints_ordered(src_ip: &[u8], src_port: u16, dst_ip: &[u8], dst_port: u16) -> bool {
    match src_ip.cmp(dst_ip) {
        std::cmp::Ordering::Less => true,
        std::cmp::Ordering::Greater => false,
        std::cmp::Ordering::Equal => src_port <= dst_port,
    }
}

fn pad_ip(ip: &[u8]) -> [u8; 16] {
    let mut out = [0u8; 16];
    out[..ip.len()].copy_from_slice(ip);
    out
}

pub fn hash_to_bucket(seed: u64, key: &FlowKey, buckets: u32) -> u32 {
    let mut h = seed ^ key.protocol as u64;
    h = mix(h ^ u64::from(key.a_port) << 16 | u64::from(key.b_port));
    for b in key.a.iter().take(key.a_len as usize) {
        h = mix(h ^ u64::from(*b));
    }
    for b in key.b.iter().take(key.b_len as usize) {
        h = mix(h ^ u64::from(*b));
    }
    (h as u32) & (buckets - 1)
}

fn mix(mut x: u64) -> u64 {
    x ^= x >> 33;
    x = x.wrapping_mul(0xff51_afd7_ed55_8ccd);
    x ^= x >> 33;
    x
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query_and_response_same_bucket() {
        let q = FlowKey::from_endpoints(17, &[10, 0, 0, 1], 49152, &[10, 0, 0, 2], 53);
        let r = FlowKey::from_endpoints(17, &[10, 0, 0, 2], 53, &[10, 0, 0, 1], 49152);
        assert_eq!(q, r);
        let seed = 42;
        let buckets = 1024;
        assert_eq!(
            hash_to_bucket(seed, &q, buckets),
            hash_to_bucket(seed, &r, buckets)
        );
    }
}
