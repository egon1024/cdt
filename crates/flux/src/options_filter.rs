use std::path::{Path, PathBuf};

use crate::filter::{
    CompiledFilter, EndpointIndex, EndpointResolver, EvalContext, Predicate, build_compiled,
    compile_saved_filter, effective_qr, embedded_iana_tlds, load_named_filter, parse_filter_flags,
    predicate_requires_response, preset_by_name,
};

use super::{FluxOptions, OptionsError};

impl FluxOptions {
    pub fn compile_filter(
        &self,
        _resolver: &dyn EndpointResolver,
    ) -> Result<CompiledFilter, OptionsError> {
        let mut parts =
            parse_filter_flags(&self.filter_tokens).map_err(|e| OptionsError::InvalidValue {
                name: "filter".into(),
                detail: e.to_string(),
            })?;

        if let Some(preset) = &self.preset {
            let (_, pred) = preset_by_name(preset).ok_or_else(|| OptionsError::InvalidValue {
                name: "+preset".into(),
                detail: format!("unknown preset {preset}"),
            })?;
            parts.push(pred);
        }

        if let Some(name) = &self.saved_filter {
            let dirs = self.filter_search_dirs();
            let (_path, content) =
                load_named_filter(name, &dirs).map_err(|e| OptionsError::InvalidValue {
                    name: "+filter".into(),
                    detail: e.to_string(),
                })?;
            let pred = compile_saved_filter(&content).map_err(|e| OptionsError::InvalidValue {
                name: "+filter".into(),
                detail: e.to_string(),
            })?;
            parts.push(pred);
        }

        for path in &self.filter_files {
            let content =
                std::fs::read_to_string(path).map_err(|e| OptionsError::InvalidValue {
                    name: "+filter-file".into(),
                    detail: e.to_string(),
                })?;
            let pred = compile_saved_filter(&content).map_err(|e| OptionsError::InvalidValue {
                name: "+filter-file".into(),
                detail: e.to_string(),
            })?;
            parts.push(pred);
        }

        let root = if parts.is_empty() {
            Predicate::True
        } else if parts.len() == 1 {
            parts.into_iter().next().unwrap()
        } else {
            Predicate::All(parts)
        };

        let auto_response =
            self.qr.is_none() && (predicate_requires_response(&root) || self.auto_response_view());
        let qr = effective_qr(self.qr, auto_response);

        let label = if let Some(p) = &self.preset {
            format!("preset={p}")
        } else if let Some(n) = &self.saved_filter {
            format!("filter={n}")
        } else if !self.filter_files.is_empty() {
            let names: Vec<String> = self
                .filter_files
                .iter()
                .map(|p| {
                    Path::new(p)
                        .file_name()
                        .and_then(|s| s.to_str())
                        .map(|s| s.to_string())
                        .unwrap_or_else(|| p.clone())
                })
                .collect();
            format!("filter-file={}", names.join(","))
        } else if !self.filter_tokens.is_empty() {
            self.filter_tokens.join(" ")
        } else {
            String::new()
        };

        Ok(build_compiled(root, label, qr))
    }

    pub fn build_eval_context(&self, resolver: &dyn EndpointResolver) -> EvalContext {
        let mut endpoints = EndpointIndex::default();
        endpoints.merge(&EndpointIndex::from_tokens(&self.initiator, resolver));
        endpoints.merge(&EndpointIndex::from_tokens(&self.responder, resolver));
        endpoints.merge(&EndpointIndex::from_tokens(&self.src, resolver));
        endpoints.merge(&EndpointIndex::from_tokens(&self.dst, resolver));
        let unknown_tlds = self.known_tlds();
        EvalContext {
            endpoints,
            unknown_tlds,
        }
    }

    pub fn filter_search_dirs(&self) -> Vec<PathBuf> {
        let mut dirs = Vec::new();
        if let Some(config) = std::env::var_os("XDG_CONFIG_HOME") {
            dirs.push(PathBuf::from(config).join("cdt/flux/filters"));
        }
        dirs.push(PathBuf::from("/etc/cdt/flux/filters"));
        dirs
    }

    pub fn known_tlds(&self) -> Vec<String> {
        if let Some(path) = &self.tld_list_path {
            if let Ok(content) = std::fs::read_to_string(path) {
                return content
                    .lines()
                    .filter(|l| !l.is_empty() && !l.starts_with('#'))
                    .map(|s| s.to_ascii_lowercase())
                    .collect();
            }
        }
        embedded_iana_tlds()
    }

    fn auto_response_view(&self) -> bool {
        use super::ViewId;
        self.batch_views
            .iter()
            .any(|v| matches!(v, ViewId::Ede | ViewId::SrcXEde))
    }
}
