use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Manifest {
    pub bundle: Bundle,
    pub components: Vec<Component>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Bundle {
    pub name: String,
    pub version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Component {
    pub name: String,
    #[serde(rename = "crate")]
    pub crate_name: String,
    pub binary: String,
    pub version: String,
    pub description: String,
}

pub fn embedded_manifest_toml() -> &'static str {
    include_str!(concat!(env!("OUT_DIR"), "/cdt-manifest.toml"))
}

pub fn load_embedded() -> Manifest {
    parse_manifest(embedded_manifest_toml()).expect("embedded manifest must be valid")
}

pub fn parse_manifest(contents: &str) -> Result<Manifest, toml::de::Error> {
    toml::from_str(contents)
}
