use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct DelvePaths {
    pub cache_dir: PathBuf,
    pub data_dir: PathBuf,
    pub sessions_dir: PathBuf,
    pub cache_db: PathBuf,
    pub sessions_db: PathBuf,
    pub config_file: PathBuf,
}

impl DelvePaths {
    pub fn platform() -> Self {
        let cache_dir = directories::BaseDirs::new()
            .map(|dirs| dirs.cache_dir().join("cdt/delve"))
            .unwrap_or_else(|| PathBuf::from(".cdt/cache/delve"));
        let data_dir = directories::BaseDirs::new()
            .map(|dirs| dirs.data_dir().join("cdt/delve"))
            .unwrap_or_else(|| PathBuf::from(".cdt/data/delve"));
        let config_file = directories::BaseDirs::new()
            .map(|dirs| dirs.config_dir().join("cdt/delve.yaml"))
            .unwrap_or_else(|| PathBuf::from(".cdt/config/delve.yaml"));
        Self::from_dirs(cache_dir, data_dir, config_file)
    }

    #[allow(dead_code)]
    pub fn from_root(root: &Path) -> Self {
        Self::from_dirs(
            root.join("cache"),
            root.join("data"),
            root.join("config/delve.yaml"),
        )
    }

    fn from_dirs(cache_dir: PathBuf, data_dir: PathBuf, config_file: PathBuf) -> Self {
        let sessions_dir = data_dir.join("sessions");
        let cache_db = cache_dir.join("cache.sqlite");
        let sessions_db = data_dir.join("sessions.sqlite");
        Self {
            cache_dir,
            data_dir,
            sessions_dir,
            cache_db,
            sessions_db,
            config_file,
        }
    }

    pub fn config_file(&self) -> &Path {
        &self.config_file
    }

    pub fn ensure_cache_dir(&self) -> std::io::Result<()> {
        std::fs::create_dir_all(&self.cache_dir)
    }

    pub fn ensure_data_dirs(&self) -> std::io::Result<()> {
        std::fs::create_dir_all(&self.data_dir)?;
        std::fs::create_dir_all(&self.sessions_dir)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_root_layout() {
        let root = PathBuf::from("/tmp/delve-test-root");
        let paths = DelvePaths::from_root(&root);
        assert_eq!(paths.cache_db, root.join("cache/cache.sqlite"));
        assert_eq!(paths.sessions_dir, root.join("data/sessions"));
        assert_eq!(paths.sessions_db, root.join("data/sessions.sqlite"));
    }
}
