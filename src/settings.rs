//! everything that can be changed through the management api, persisted as a json file

use ritualistic::management::{IDReason, IPReason, PubKeyReason};

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
#[serde(default)]
pub struct Settings {
    pub name: String,
    pub description: String,
    pub icon: String,

    /// the whitelist: these people and the people they follow can write
    pub allowed_pubkeys: Vec<PubKeyReason>,

    /// events that were deleted and can't be written again
    pub banned_events: Vec<IDReason>,

    /// if not empty, only these kinds are accepted
    pub allowed_kinds: Vec<ritualistic::Kind>,

    /// these kinds are never accepted
    pub disallowed_kinds: Vec<ritualistic::Kind>,

    pub blocked_ips: Vec<IPReason>,
}

impl Settings {
    /// load from `path`, or return the defaults if it doesn't exist yet
    pub fn load(path: &std::path::Path) -> std::io::Result<Self> {
        match std::fs::read(path) {
            Ok(data) => serde_json::from_slice(&data)
                .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidData, err)),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(Self {
                name: "txstr server".to_string(),
                ..Default::default()
            }),
            Err(err) => Err(err),
        }
    }

    /// write to `path` atomically
    pub fn save(&self, path: &std::path::Path) -> std::io::Result<()> {
        let tmp = path.with_extension("json.tmp");
        std::fs::write(
            &tmp,
            serde_json::to_vec_pretty(self).expect("settings always serialize"),
        )?;
        std::fs::rename(tmp, path)
    }

    pub fn is_kind_allowed(&self, kind: ritualistic::Kind) -> bool {
        !self.disallowed_kinds.contains(&kind)
            && (self.allowed_kinds.is_empty() || self.allowed_kinds.contains(&kind))
    }
}
