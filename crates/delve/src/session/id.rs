use ulid::Ulid;

pub fn new_session_id() -> String {
    Ulid::new().to_string()
}

pub fn resolve_prefix(prefix: &str, ids: &[String]) -> Option<String> {
    let matches: Vec<&String> = ids.iter().filter(|id| id.starts_with(prefix)).collect();
    match matches.len() {
        0 => None,
        1 => Some(matches[0].clone()),
        _ => None,
    }
}

pub fn is_ambiguous_prefix(prefix: &str, ids: &[String]) -> bool {
    ids.iter()
        .filter(|id| id.starts_with(prefix))
        .take(2)
        .count()
        > 1
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_unique_prefix() {
        let ids = vec![
            "01ARZ3NDEKTSV4RRFFQ69G5FAV".into(),
            "01BRZ3NDEKTSV4RRFFQ69G5FBV".into(),
        ];
        assert_eq!(
            resolve_prefix("01ARZ3NDEK", &ids),
            Some("01ARZ3NDEKTSV4RRFFQ69G5FAV".into())
        );
    }

    #[test]
    fn ambiguous_prefix_detected() {
        let ids = vec![
            "01ARZ3NDEKTSV4RRFFQ69G5FAV".into(),
            "01ARZ3NDEKTSV4RRFFQ69G5FBV".into(),
        ];
        assert!(is_ambiguous_prefix("01ARZ3NDEK", &ids));
    }
}
