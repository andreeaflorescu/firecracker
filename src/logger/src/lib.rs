// Workaround to `macro_reexport`.
#[macro_use]
extern crate lazy_static;
extern crate libc;
extern crate log;
extern crate serde;
#[macro_use]
extern crate serde_derive;
extern crate serde_json;
extern crate utils;

pub mod error;
pub mod logger;
pub mod metrics;

pub use log::Level::*;
pub use log::*;
pub use logger::LOGGER;
pub use metrics::{Metric, Metrics, METRICS};

use std::io::Write;

/// Auxiliary function to flush a message to a entity implementing `Write` and `Send` traits.
// This is used to either flush human-readable logs or metrics.
pub fn write_to_destination(
    mut msg: String,
    buffer: &mut (dyn Write + Send),
) -> Result<(), std::io::Error> {
    msg = format!("{}\n", msg);
    buffer.write(&msg.as_bytes())?;
    buffer.flush()
}
