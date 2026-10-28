//! Block sources for carving: anything that can be read by absolute offset.
//!
//! Two flavours:
//!
//! * [`DirectSource`] wraps any `Read + Seek` (raw files, VMDK, VHD/VHDX).
//!   Reader panics are caught and reported as read errors.
//! * [`GuardedSource`] runs every read on a helper thread with a time budget.
//!   A damaged EWF segment can make a chunk decode spin forever; when that
//!   happens the stuck reader is abandoned, a fresh one is opened and the
//!   scanner skips past the window. Ported from masstin's EVTX carver.

use std::io::{Read, Seek, SeekFrom};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::mpsc;
use std::time::Duration;

/// Why a block could not be delivered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BlockError {
    /// The read failed; the caller skips the block.
    Io(String),
    /// The read exceeded the time budget; the reader was abandoned.
    Stalled,
    /// No reader is available any more (reopen failed).
    Unavailable(String),
}

impl std::fmt::Display for BlockError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BlockError::Io(e) => write!(f, "read error: {e}"),
            BlockError::Stalled => write!(f, "read stalled"),
            BlockError::Unavailable(e) => write!(f, "source unavailable: {e}"),
        }
    }
}

/// A byte source addressed by absolute offset.
pub trait BlockSource {
    /// Total size in bytes.
    fn size(&self) -> u64;
    /// Human-readable name used in diagnostics.
    fn label(&self) -> &str;
    /// Bytes at `offset`. Shorter than `len` only at the end of the source;
    /// empty when `offset` is at or past the end.
    fn read_block(&mut self, offset: u64, len: usize) -> Result<Vec<u8>, BlockError>;
    /// Number of reads abandoned for exceeding the time budget.
    fn stalls(&self) -> usize {
        0
    }
}

fn read_fully<R: Read + Seek>(r: &mut R, offset: u64, len: usize) -> std::io::Result<Vec<u8>> {
    r.seek(SeekFrom::Start(offset))?;
    let mut buf = vec![0u8; len];
    let mut got = 0usize;
    while got < len {
        match r.read(&mut buf[got..]) {
            Ok(0) => break,
            Ok(n) => got += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    buf.truncate(got);
    Ok(buf)
}

/// Plain seekable reader.
pub struct DirectSource<R: Read + Seek> {
    inner: R,
    size: u64,
    label: String,
}

impl<R: Read + Seek> DirectSource<R> {
    pub fn new(inner: R, size: u64, label: impl Into<String>) -> Self {
        DirectSource { inner, size, label: label.into() }
    }
}

impl<R: Read + Seek> BlockSource for DirectSource<R> {
    fn size(&self) -> u64 {
        self.size
    }

    fn label(&self) -> &str {
        &self.label
    }

    fn read_block(&mut self, offset: u64, len: usize) -> Result<Vec<u8>, BlockError> {
        if offset >= self.size {
            return Ok(Vec::new());
        }
        let len = len.min((self.size - offset) as usize);
        match catch_unwind(AssertUnwindSafe(|| read_fully(&mut self.inner, offset, len))) {
            Ok(Ok(b)) => Ok(b),
            Ok(Err(e)) => Err(BlockError::Io(e.to_string())),
            Err(p) => Err(BlockError::Io(format!(
                "reader panicked: {}",
                crate::windows::diag::panic_message(&*p)
            ))),
        }
    }
}

/// Reader driven from a helper thread with a per-read time budget.
pub struct GuardedSource<R: Read + Seek + Send + 'static> {
    inner: Option<R>,
    reopen: Box<dyn Fn() -> Result<R, String> + Send>,
    timeout: Duration,
    size: u64,
    label: String,
    stalls: usize,
}

impl<R: Read + Seek + Send + 'static> GuardedSource<R> {
    pub fn new(
        inner: R,
        size: u64,
        label: impl Into<String>,
        timeout: Duration,
        reopen: impl Fn() -> Result<R, String> + Send + 'static,
    ) -> Self {
        GuardedSource {
            inner: Some(inner),
            reopen: Box::new(reopen),
            timeout,
            size,
            label: label.into(),
            stalls: 0,
        }
    }
}

impl<R: Read + Seek + Send + 'static> BlockSource for GuardedSource<R> {
    fn size(&self) -> u64 {
        self.size
    }

    fn label(&self) -> &str {
        &self.label
    }

    fn stalls(&self) -> usize {
        self.stalls
    }

    fn read_block(&mut self, offset: u64, len: usize) -> Result<Vec<u8>, BlockError> {
        if offset >= self.size {
            return Ok(Vec::new());
        }
        let len = len.min((self.size - offset) as usize);
        let mut reader = match self.inner.take() {
            Some(r) => r,
            None => (self.reopen)().map_err(BlockError::Unavailable)?,
        };
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let result = read_fully(&mut reader, offset, len);
            let _ = tx.send((result, reader));
        });
        match rx.recv_timeout(self.timeout) {
            Ok((Ok(buf), reader)) => {
                self.inner = Some(reader);
                Ok(buf)
            }
            Ok((Err(e), reader)) => {
                self.inner = Some(reader);
                Err(BlockError::Io(e.to_string()))
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                // The stuck thread keeps the old reader; it is dropped whenever
                // (if ever) the read returns. The next call reopens.
                self.stalls += 1;
                Err(BlockError::Stalled)
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => Err(BlockError::Io("reader thread panicked".to_string())),
        }
    }
}

/// In-memory source, handy for tests and for carving small files.
pub type MemorySource = DirectSource<std::io::Cursor<Vec<u8>>>;

impl DirectSource<std::io::Cursor<Vec<u8>>> {
    pub fn from_bytes(bytes: Vec<u8>, label: impl Into<String>) -> Self {
        let size = bytes.len() as u64;
        DirectSource::new(std::io::Cursor::new(bytes), size, label)
    }
}
