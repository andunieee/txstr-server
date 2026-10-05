//! the write policy, storage and management for the server

use ritualistic::EventDatabase;
use ritualistic::management::{IDReason, IPReason, Method, PubKeyReason};
use ritualistic::relay_information::RelayInformationDocument;
use ritualistic::{Event, Filter, Kind, PubKey};

use crate::settings::Settings;

/// max events returned for a single filter
const MAX_LIMIT: usize = 500;

const KIND_FOLLOW_LIST: Kind = Kind(3);
const KIND_DELETION: Kind = Kind(5);
const KIND_NOTE: Kind = Kind(1);
const KIND_COMMENT: Kind = Kind(1111);

const MANAGEMENT_METHODS: &[&str] = &[
    "allowpubkey",
    "unallowpubkey",
    "listallowedpubkeys",
    "banevent",
    "unbanevent",
    "listbannedevents",
    "changerelayname",
    "changerelaydescription",
    "changerelayicon",
    "allowkind",
    "disallowkind",
    "listallowedkinds",
    "listdisallowedkinds",
    "blockip",
    "unblockip",
    "listblockedips",
];

pub struct Options {
    /// where events and settings are stored
    pub data_dir: std::path::PathBuf,

    /// who can use the management api (they are also implicitly whitelisted)
    pub admins: Vec<PubKey>,

    /// reject notes and comments that link to images
    pub no_images: bool,
}

pub struct Server {
    db: ritualistic::LMDBEventDatabase,
    settings: Settings,
    settings_path: std::path::PathBuf,
    admins: Vec<PubKey>,
    no_images: bool,

    /// whitelisted people plus everybody they follow, recomputed whenever any of that changes
    writers: std::collections::HashSet<PubKey>,
}

#[derive(Debug, thiserror::Error)]
pub enum OpenError {
    #[error("database: {0}")]
    Database(#[from] ritualistic::database::DatabaseError),

    #[error("settings: {0}")]
    Settings(#[from] std::io::Error),
}

impl Server {
    pub fn open(options: Options) -> Result<Self, OpenError> {
        std::fs::create_dir_all(&options.data_dir)?;
        let db = ritualistic::LMDBEventDatabase::open(options.data_dir.join("events"))?;
        let settings_path = options.data_dir.join("settings.json");
        let settings = Settings::load(&settings_path)?;

        let mut server = Self {
            db,
            settings,
            settings_path,
            admins: options.admins,
            no_images: options.no_images,
            writers: Default::default(),
        };
        server.recompute_writers();
        Ok(server)
    }

    pub fn information(&self) -> RelayInformationDocument {
        RelayInformationDocument {
            name: self.settings.name.clone(),
            description: self.settings.description.clone(),
            icon: self.settings.icon.clone(),
            pubkey: self.admins.first().copied(),
            ..Default::default()
        }
    }

    fn is_whitelisted(&self, pubkey: &PubKey) -> bool {
        self.admins.contains(pubkey)
            || self
                .settings
                .allowed_pubkeys
                .iter()
                .any(|a| a.pubkey == *pubkey)
    }

    fn whitelisted(&self) -> impl Iterator<Item = PubKey> + '_ {
        self.admins
            .iter()
            .copied()
            .chain(self.settings.allowed_pubkeys.iter().map(|a| a.pubkey))
    }

    fn recompute_writers(&mut self) {
        let whitelisted: Vec<PubKey> = self.whitelisted().collect();
        let mut writers: std::collections::HashSet<PubKey> = whitelisted.iter().copied().collect();

        let mut filter = [Filter {
            kinds: Some(vec![KIND_FOLLOW_LIST]),
            authors: Some(whitelisted),
            ..Default::default()
        }];
        match self.db.query_events(&mut filter) {
            Ok(results) => {
                for follow_list in results {
                    for tag in follow_list.tags.0.iter() {
                        if tag.len() >= 2
                            && tag[0] == "p"
                            && let Ok(pubkey) = tag[1].parse::<PubKey>()
                        {
                            writers.insert(pubkey);
                        }
                    }
                }
            }
            Err(err) => log::error!("failed to load follow lists: {}", err),
        }

        self.writers = writers;
    }

    fn save_settings(&self) -> Result<(), String> {
        self.settings.save(&self.settings_path).map_err(|err| {
            log::error!("failed to save settings: {}", err);
            format!("failed to save settings: {}", err)
        })
    }

    fn store(&self, event: &Event) -> Result<(), ritualistic::database::DatabaseError> {
        if event.kind.is_ephemeral() {
            return Ok(());
        }
        if event.kind.is_replaceable() {
            return self.db.replace_event(event, false);
        }
        if event.kind.is_addressable() {
            return self.db.replace_event(event, true);
        }

        if event.kind == KIND_DELETION {
            for tag in event.tags.find_all("e") {
                let Ok(id) = tag[1].parse::<ritualistic::ID>() else {
                    continue;
                };
                let mut filter = [Filter {
                    ids: Some(vec![id]),
                    ..Default::default()
                }];
                // only the author can delete their stuff
                let owned = self
                    .db
                    .query_events(&mut filter)?
                    .any(|target| id == target.id && target.pubkey.0 == event.pubkey.0);
                if owned {
                    self.db.delete_event(id.short())?;
                }
            }
        }

        self.db.save_event(event)
    }
}

impl ritualistic::server::CustomRelay for Server {
    fn handle_event(&mut self, event: &Event) -> Result<(), String> {
        if self.settings.banned_events.iter().any(|b| b.id == event.id) {
            return Err("blocked: this event is banned".to_string());
        }
        if !self.writers.contains(&event.pubkey) {
            return Err("restricted: you're not allowed to write here".to_string());
        }
        if !self.settings.is_kind_allowed(event.kind) {
            return Err(format!("blocked: kind {} is not allowed", event.kind));
        }
        if self.no_images
            && (event.kind == KIND_NOTE || event.kind == KIND_COMMENT)
            && crate::images::has_image_url(&event.content)
        {
            return Err("blocked: images are not allowed".to_string());
        }

        match self.store(event) {
            Ok(()) => {}
            Err(ritualistic::database::DatabaseError::DuplicateEvent) => {
                return Err("duplicate: already have this event".to_string());
            }
            Err(err) => {
                log::error!("failed to store {}: {}", event.id, err);
                return Err("error: failed to store event".to_string());
            }
        }

        if event.kind == KIND_FOLLOW_LIST && self.is_whitelisted(&event.pubkey) {
            self.recompute_writers();
        }

        Ok(())
    }

    fn handle_request(&mut self, filter: &Filter) -> Result<Vec<Event>, String> {
        let mut filter = [Filter {
            limit: Some(filter.limit.unwrap_or(MAX_LIMIT).min(MAX_LIMIT)),
            ..filter.clone()
        }];

        let results = self
            .db
            .query_events(&mut filter)
            .map_err(|err| err.to_string())?;
        Ok(results
            .map(|event| {
                rkyv::deserialize::<Event, rkyv::rancor::Error>(&*event)
                    .expect("archived events always deserialize")
            })
            .collect())
    }

    fn check_ip(&mut self, ip: &std::net::IpAddr) -> Result<(), String> {
        match self.settings.blocked_ips.iter().find(|b| b.ip == *ip) {
            Some(_) => Err("blocked".to_string()),
            None => Ok(()),
        }
    }

    fn supported_management_methods(&mut self, caller: &PubKey) -> Vec<String> {
        if self.admins.contains(caller) {
            MANAGEMENT_METHODS.iter().map(|m| m.to_string()).collect()
        } else {
            Vec::new()
        }
    }

    fn handle_management(
        &mut self,
        caller: &PubKey,
        method: &Method,
        info: &mut RelayInformationDocument,
    ) -> Result<serde_json::Value, String> {
        log::info!("{} called {}", caller.to_hex(), method.name());

        let s = &mut self.settings;
        match method {
            // whitelist
            Method::AllowPubKey(pubkey, reason) => {
                // admins are implicitly whitelisted, don't persist a redundant entry
                s.allowed_pubkeys.retain(|a| a.pubkey != *pubkey);
                if !self.admins.contains(pubkey) {
                    s.allowed_pubkeys.push(PubKeyReason {
                        pubkey: *pubkey,
                        reason: reason.clone(),
                    });
                }
                self.recompute_writers();
            }
            Method::UnallowPubKey(pubkey, _) => {
                s.allowed_pubkeys.retain(|a| a.pubkey != *pubkey);
                self.recompute_writers();
            }
            Method::ListAllowedPubKeys => {
                let listed: Vec<PubKeyReason> = self
                    .admins
                    .iter()
                    .copied()
                    .map(|pubkey| PubKeyReason {
                        pubkey,
                        reason: None,
                    })
                    .chain(
                        s.allowed_pubkeys
                            .iter()
                            .filter(|a| !self.admins.contains(&a.pubkey))
                            .cloned(),
                    )
                    .collect();
                return Ok(serde_json::json!(listed));
            }

            // events
            Method::BanEvent(id, reason) => {
                s.banned_events.retain(|b| b.id != *id);
                s.banned_events.push(IDReason {
                    id: *id,
                    reason: reason.clone(),
                });
                if let Err(err) = self.db.delete_event(id.short()) {
                    log::error!("failed to delete banned event {}: {}", id, err);
                }
            }
            Method::UnbanEvent(id, _) => s.banned_events.retain(|b| b.id != *id),
            Method::ListBannedEvents => return Ok(serde_json::json!(s.banned_events)),

            // metadata
            Method::ChangeRelayName(name) => {
                s.name = name.clone();
                info.name = name.clone();
            }
            Method::ChangeRelayDescription(description) => {
                s.description = description.clone();
                info.description = description.clone();
            }
            Method::ChangeRelayIcon(icon) => {
                s.icon = icon.clone();
                info.icon = icon.clone();
            }

            // kinds
            Method::AllowKind(kind) => {
                s.disallowed_kinds.retain(|k| k != kind);
                if !s.allowed_kinds.contains(kind) {
                    s.allowed_kinds.push(*kind);
                }
            }
            Method::DisallowKind(kind) => {
                s.allowed_kinds.retain(|k| k != kind);
                if !s.disallowed_kinds.contains(kind) {
                    s.disallowed_kinds.push(*kind);
                }
            }
            Method::ListAllowedKinds => return Ok(serde_json::json!(s.allowed_kinds)),
            Method::ListDisallowedKinds => return Ok(serde_json::json!(s.disallowed_kinds)),

            // ips
            Method::BlockIP(ip, reason) => {
                s.blocked_ips.retain(|b| b.ip != *ip);
                s.blocked_ips.push(IPReason {
                    ip: *ip,
                    reason: reason.clone(),
                });
            }
            Method::UnblockIP(ip) => s.blocked_ips.retain(|b| b.ip != *ip),
            Method::ListBlockedIPs => return Ok(serde_json::json!(s.blocked_ips)),

            _ => return Err(format!("method '{}' not supported", method.name())),
        }

        self.save_settings()?;
        Ok(serde_json::Value::Bool(true))
    }
}
