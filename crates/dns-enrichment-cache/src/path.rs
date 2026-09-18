use std::path::PathBuf;

/// Default enrichment SQLite path: `$XDG_DATA_HOME/cdt/delve/enrichment.sqlite`.
pub fn default_enrichment_db_path() -> PathBuf {
    directories::BaseDirs::new()
        .map(|dirs| dirs.data_dir().join("cdt/delve/enrichment.sqlite"))
        .unwrap_or_else(|| PathBuf::from(".cdt/data/delve/enrichment.sqlite"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_path_ends_with_enrichment_sqlite() {
        let path = default_enrichment_db_path();
        assert_eq!(
            path.file_name().and_then(|name| name.to_str()),
            Some("enrichment.sqlite")
        );
        let parent = path.parent().expect("parent");
        assert!(parent.ends_with("cdt/delve") || parent.ends_with(".cdt/data/delve"));
    }
}
