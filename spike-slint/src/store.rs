//! Small JSON document store for user data.
//!
//! Writes go through a temporary file and a rename so a crash mid-save can never
//! leave a truncated server list behind.

use std::path::{Path, PathBuf};

use serde::de::DeserializeOwned;
use serde::Serialize;

use crate::error::Result;

pub struct Store {
    dir: PathBuf,
}

impl Store {
    pub fn new(dir: PathBuf) -> Result<Self> {
        std::fs::create_dir_all(&dir)?;
        Ok(Self { dir })
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.join(format!("{name}.json"))
    }

    /// Load a document, falling back to `Default` for a missing *or* corrupt file.
    /// Losing preferences is annoying; refusing to launch is worse.
    pub fn load<T: DeserializeOwned + Default>(&self, name: &str) -> T {
        let path = self.path(name);
        let Ok(text) = std::fs::read_to_string(&path) else {
            return T::default();
        };
        // Notepad and PowerShell write UTF-8 with a byte-order mark, which
        // serde_json rejects outright. A hand-edited file must not cost the
        // user their server list.
        let text = text.strip_prefix('\u{feff}').unwrap_or(&text);
        match serde_json::from_str(text) {
            Ok(value) => value,
            Err(_) => {
                // Keep the damaged file around so the user can recover by hand.
                let _ = std::fs::rename(&path, path.with_extension("json.bak"));
                T::default()
            }
        }
    }

    pub fn save<T: Serialize>(&self, name: &str, value: &T) -> Result<()> {
        let final_path = self.path(name);
        let tmp_path = final_path.with_extension("json.tmp");
        std::fs::write(&tmp_path, serde_json::to_vec_pretty(value)?)?;
        std::fs::rename(&tmp_path, &final_path)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;

    #[derive(Serialize, Deserialize, Default, PartialEq, Debug)]
    struct Doc {
        value: u32,
    }

    fn temp_store(label: &str) -> Store {
        let dir = std::env::temp_dir().join(format!("aurora-store-test-{label}"));
        let _ = std::fs::remove_dir_all(&dir);
        Store::new(dir).unwrap()
    }

    #[test]
    fn round_trips_a_document() {
        let store = temp_store("roundtrip");
        store.save("doc", &Doc { value: 42 }).unwrap();
        assert_eq!(store.load::<Doc>("doc"), Doc { value: 42 });
    }

    #[test]
    fn missing_document_yields_the_default() {
        let store = temp_store("missing");
        assert_eq!(store.load::<Doc>("nope"), Doc::default());
    }

    #[test]
    fn utf8_bom_does_not_discard_the_document() {
        // Editing the file in Notepad is enough to prepend a BOM; losing every
        // configured server over it would be indefensible.
        let store = temp_store("bom");
        std::fs::write(
            store.dir().join("doc.json"),
            "\u{feff}{\"value\":7}".as_bytes(),
        )
        .unwrap();
        assert_eq!(store.load::<Doc>("doc"), Doc { value: 7 });
        assert!(!store.dir().join("doc.json.bak").exists());
    }

    #[test]
    fn corrupt_document_is_quarantined_rather_than_fatal() {
        let store = temp_store("corrupt");
        std::fs::write(store.dir().join("doc.json"), b"{ not json").unwrap();
        assert_eq!(store.load::<Doc>("doc"), Doc::default());
        assert!(store.dir().join("doc.json.bak").exists());
    }
}
