use dns_core::response::DnsResponse;

const DEFAULT_TTL: u64 = 60;

/// TTL to store for a cached response (minimum across relevant records).
pub fn cache_ttl_seconds(response: &DnsResponse) -> u64 {
    let positive = min_ttl(&response.answers);
    if positive > 0 {
        return positive;
    }

    if response.rcode == 3 {
        return soa_minimum_ttl(response).unwrap_or(DEFAULT_TTL);
    }

    min_ttl(&response.authorities)
        .max(min_ttl(&response.additionals))
        .max(DEFAULT_TTL)
}

fn min_ttl(records: &[dns_core::response::DnsRecord]) -> u64 {
    records
        .iter()
        .map(|record| u64::from(record.ttl))
        .min()
        .unwrap_or(0)
}

fn soa_minimum_ttl(response: &DnsResponse) -> Option<u64> {
    response
        .authorities
        .iter()
        .filter(|record| record.rtype == "SOA")
        .map(|record| parse_soa_minimum(&record.rdata))
        .max()
}

fn parse_soa_minimum(rdata: &str) -> u64 {
    // Hickory SOA text: mname rname serial refresh retry expire minimum
    let parts: Vec<&str> = rdata.split_whitespace().collect();
    if parts.len() >= 7 {
        parts[6].parse().unwrap_or(DEFAULT_TTL)
    } else {
        DEFAULT_TTL
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dns_core::EdnsMeta;
    use dns_core::name::DomainName;
    use dns_core::response::{DnsRecord, DnsResponse};

    fn record(name: &str, rtype: &str, ttl: u32, rdata: &str) -> DnsRecord {
        DnsRecord {
            name: DomainName::parse(name).expect("name"),
            rtype: rtype.into(),
            rclass: "IN".into(),
            ttl,
            rdata: rdata.into(),
        }
    }

    fn empty_response() -> DnsResponse {
        DnsResponse {
            id: 1,
            rcode: 0,
            rcode_text: "NOERROR".into(),
            authoritative: false,
            truncated: false,
            recursion_desired: false,
            recursion_available: false,
            authentic_data: false,
            checking_disabled: false,
            answers: vec![],
            authorities: vec![],
            additionals: vec![],
            edns: EdnsMeta::default(),
        }
    }

    #[test]
    fn uses_minimum_answer_ttl() {
        let response = DnsResponse {
            answers: vec![
                record("example.com.", "A", 300, "1.2.3.4"),
                record("example.com.", "A", 120, "1.2.3.5"),
            ],
            ..empty_response()
        };
        assert_eq!(cache_ttl_seconds(&response), 120);
    }

    #[test]
    fn nxdomain_uses_soa_minimum() {
        let response = DnsResponse {
            rcode: 3,
            rcode_text: "NXDOMAIN".into(),
            authorities: vec![record(
                "example.com.",
                "SOA",
                3600,
                "ns.example.com. host.example.com. 1 7200 3600 1209600 900",
            )],
            ..empty_response()
        };
        assert_eq!(cache_ttl_seconds(&response), 900);
    }
}
