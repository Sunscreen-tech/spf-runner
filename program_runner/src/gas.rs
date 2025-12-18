//! Gas tracking for FHE operations.

use log::info;

/// Tracks gas consumption across FHE operations.
pub(crate) struct GasTracker(u32);

impl GasTracker {
    /// Create a new gas tracker with zero initial consumption.
    pub fn new() -> Self {
        info!("Initial gas consumption set as 0");
        Self(0)
    }

    /// Charge gas for an operation and log the consumption.
    pub fn charge(&mut self, amount: u32, description: &str) {
        self.0 += amount;
        info!(
            "{description} consumes {amount} gas and the accumulated gas consumption is {}",
            self.0
        );
    }
}
