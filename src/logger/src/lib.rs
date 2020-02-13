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
// TODO: Either make the modules public or use `pub use log::*; pub use metrics::{Metric, Metrics, METRICS}`.
// We shouldn't expose the same functionality in two ways.
pub mod logger;
pub mod metrics;

pub use log::Level::*;
pub use log::*;
pub use logger::LOGGER;
pub use metrics::{Metric, Metrics, METRICS};

use std::io::Write;

/// Auxiliary function to flush a message to a entity implementing `Write` and `Send` traits.
// This is used to either flush human-readable logs or metrics.
// TODO: msg shouldn't be mut;
// TODO: This function doesn't need to be public;
// TODO: nit: buffer can be named destination
pub fn write_to_destination(
    msg: String,
    buffer: &mut (dyn Write + Send),
) -> Result<(), std::io::Error> {
    buffer.write(&(format!("{}\n", msg)).as_bytes())?;
    buffer.flush()
}
