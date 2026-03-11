//! Event log reader — reads NDJSON events from a completed trace.
//!
//! Supports two modes:
//! - `read_all()`: loads all events into memory (for small traces).
//! - `iter()`: streams events one at a time (for large traces).

use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;

use crate::event::{EventStreamHeader, OaieEvent};

/// Reads observation events from an NDJSON log file.
///
/// The first line is the [`EventStreamHeader`]; subsequent lines are events.
pub struct EventReader {
    /// Buffered reader positioned after the header line.
    reader: BufReader<File>,
    /// Parsed header from the first line.
    header: EventStreamHeader,
}

impl EventReader {
    /// Open an event log file and parse the header.
    pub fn open(path: &Path) -> std::io::Result<Self> {
        let mut reader = BufReader::new(File::open(path)?);

        let mut header_line = String::new();
        reader.read_line(&mut header_line)?;
        let header: EventStreamHeader = serde_json::from_str(header_line.trim())
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

        Ok(Self { reader, header })
    }

    /// The parsed stream header.
    pub fn header(&self) -> &EventStreamHeader {
        &self.header
    }

    /// Read all events into memory.
    ///
    /// Suitable for traces with fewer than ~100K events. For larger traces,
    /// use [`iter()`](Self::iter) to stream events one at a time.
    pub fn read_all(&mut self) -> std::io::Result<Vec<OaieEvent>> {
        let mut events = Vec::new();
        let mut line = String::new();
        loop {
            line.clear();
            let bytes_read = self.reader.read_line(&mut line)?;
            if bytes_read == 0 {
                break;
            }
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            let event: OaieEvent = serde_json::from_str(trimmed)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
            events.push(event);
        }
        Ok(events)
    }

    /// Return a streaming iterator over events.
    ///
    /// Each call to `next()` reads and parses one line. Handles large traces
    /// without loading everything into memory.
    pub fn iter(&mut self) -> EventIterator<'_> {
        EventIterator {
            reader: &mut self.reader,
        }
    }
}

/// Streaming iterator over events in an NDJSON log.
///
/// Yields `Ok(OaieEvent)` for each valid line, `Err` for parse failures.
/// Returns `None` at EOF.
pub struct EventIterator<'a> {
    reader: &'a mut BufReader<File>,
}

impl<'a> Iterator for EventIterator<'a> {
    type Item = std::io::Result<OaieEvent>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let mut line = String::new();
            match self.reader.read_line(&mut line) {
                Ok(0) => return None,
                Ok(_) => {
                    let trimmed = line.trim();
                    if trimmed.is_empty() {
                        continue;
                    }
                    return Some(
                        serde_json::from_str(trimmed)
                            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e)),
                    );
                }
                Err(e) => return Some(Err(e)),
            }
        }
    }
}
