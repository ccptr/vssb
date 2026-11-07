//! Audit log: one JSON object per line, appended to a file. Every event
//! carries the sandbox id so concurrent runs can share one log.

use anyhow::{Context, Result};
use serde_json::{Map, Value, json};
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::sync::Mutex;
use std::time::SystemTime;

pub struct Audit {
    file: Mutex<Option<File>>,
    pub id: String,
    /// Print blocked network requests to stderr.
    pub notify: bool,
}

impl Audit {
    pub fn open(path: Option<&Path>, id: String, notify: bool) -> Result<Audit> {
        let file = match path {
            Some(p) => {
                if let Some(dir) = p.parent() {
                    std::fs::create_dir_all(dir)
                        .with_context(|| format!("creating {}", dir.display()))?;
                }
                let f = OpenOptions::new()
                    .create(true)
                    .append(true)
                    .mode(0o600)
                    .custom_flags(libc::O_CLOEXEC)
                    .open(p)
                    .with_context(|| format!("opening audit log {}", p.display()))?;
                Some(f)
            }
            None => None,
        };
        Ok(Audit { file: Mutex::new(file), id, notify })
    }

    pub fn event(&self, event: &str, fields: Value) {
        let mut guard = self.file.lock().unwrap_or_else(|e| e.into_inner());
        let Some(f) = guard.as_mut() else { return };
        let mut obj = Map::new();
        obj.insert("ts".into(), json!(crate::util::rfc3339(SystemTime::now())));
        obj.insert("sandbox".into(), json!(self.id));
        obj.insert("event".into(), json!(event));
        if let Value::Object(m) = fields {
            obj.extend(m);
        }
        let mut line = Value::Object(obj).to_string();
        line.push('\n');
        // One write per line so concurrent writers with O_APPEND don't interleave.
        let _ = f.write_all(line.as_bytes());
    }
}
