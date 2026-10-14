//! Storage: composite keys for the indexes, and the append-only batch files.
//!
//! Each period has one batch file, `<data dir>/journal/<YYYY-MM>.batches`, holding framed
//! canonical batches in posting order. A torn write at the end of a file is detected by the
//! frame checksum and truncated on start-up.

pub mod keys;

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use crate::journal::batch::{self, FrameError};
use crate::model::{JournalBatch, Period};

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("batch store i/o: {0}")]
    Io(#[from] std::io::Error),
    #[error("batch file {file} is damaged at byte {offset}: {source}")]
    Damaged {
        file: PathBuf,
        offset: usize,
        source: FrameError,
    },
}

pub trait BatchStore {
    /// Appends a batch to its period's file and returns the body length written.
    fn append(&mut self, batch: &JournalBatch) -> Result<usize, StoreError>;
    /// Canonical bodies of every batch in a period, in posting order.
    fn bodies(&self, period: Period) -> Result<Vec<Vec<u8>>, StoreError>;
}

pub struct FileBatchStore {
    dir: PathBuf,
}

impl FileBatchStore {
    pub fn open(data_dir: &Path) -> Result<Self, StoreError> {
        let dir = data_dir.join("journal");
        fs::create_dir_all(&dir)?;
        Ok(Self { dir })
    }

    pub fn file_for(&self, period: Period) -> PathBuf {
        self.dir.join(format!("{period}.batches"))
    }
}

impl BatchStore for FileBatchStore {
    fn append(&mut self, batch: &JournalBatch) -> Result<usize, StoreError> {
        let encoded = batch::encode(batch);
        let framed = batch::frame(&encoded);
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.file_for(batch.period))?;
        file.write_all(&framed)?;
        file.sync_data()?;
        Ok(encoded.canonical.len())
    }

    fn bodies(&self, period: Period) -> Result<Vec<Vec<u8>>, StoreError> {
        let path = self.file_for(period);
        let bytes = match fs::read(&path) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(e.into()),
        };
        let mut out = Vec::new();
        let mut rest = bytes.as_slice();
        while !rest.is_empty() {
            let offset = bytes.len() - rest.len();
            let (body, tail) = batch::unframe(rest).map_err(|source| StoreError::Damaged {
                file: path.clone(),
                offset,
                source,
            })?;
            out.push(body.to_vec());
            rest = tail;
        }
        Ok(out)
    }
}
