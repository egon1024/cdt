use dns_resolve::{AddressFamilyRequest, ResolvedAddressFamily};

use crate::dig_options::FamilySource;

/// One-line stderr notice after address-family resolution (design.md §8).
pub fn format_family_notice(
    source: FamilySource,
    _request: AddressFamilyRequest,
    resolved: ResolvedAddressFamily,
) -> String {
    let label = resolved.label();
    let reason = match source {
        FamilySource::Default => auto_probe_reason(resolved),
        FamilySource::Minus4 => "-4".into(),
        FamilySource::Minus6 => "-6".into(),
        FamilySource::PlusFamily(family) => match family {
            AddressFamilyRequest::Auto => auto_probe_reason(resolved),
            AddressFamilyRequest::V4 => "+family=v4".into(),
            AddressFamilyRequest::V6 => "+family=v6".into(),
            AddressFamilyRequest::Both => "+family=both".into(),
        },
    };
    format!("address family: {label} ({reason})")
}

fn auto_probe_reason(resolved: ResolvedAddressFamily) -> String {
    match resolved {
        ResolvedAddressFamily::V4 => "ipv6 unreachable".into(),
        ResolvedAddressFamily::V6 | ResolvedAddressFamily::Both => "ipv6 probe ok".into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auto_v4_only_uses_unreachable_wording() {
        let notice = format_family_notice(
            FamilySource::Default,
            AddressFamilyRequest::Auto,
            ResolvedAddressFamily::V4,
        );
        assert_eq!(notice, "address family: v4-only (ipv6 unreachable)");
    }

    #[test]
    fn auto_dual_stack_uses_probe_ok_wording() {
        let notice = format_family_notice(
            FamilySource::Default,
            AddressFamilyRequest::Auto,
            ResolvedAddressFamily::Both,
        );
        assert_eq!(notice, "address family: dual-stack (ipv6 probe ok)");
    }

    #[test]
    fn explicit_flags_use_flag_labels() {
        assert_eq!(
            format_family_notice(
                FamilySource::Minus4,
                AddressFamilyRequest::V4,
                ResolvedAddressFamily::V4,
            ),
            "address family: v4-only (-4)"
        );
        assert_eq!(
            format_family_notice(
                FamilySource::Minus6,
                AddressFamilyRequest::V6,
                ResolvedAddressFamily::V6,
            ),
            "address family: v6-only (-6)"
        );
    }

    #[test]
    fn plus_family_uses_option_label() {
        assert_eq!(
            format_family_notice(
                FamilySource::PlusFamily(AddressFamilyRequest::Both),
                AddressFamilyRequest::Both,
                ResolvedAddressFamily::Both,
            ),
            "address family: dual-stack (+family=both)"
        );
    }
}
