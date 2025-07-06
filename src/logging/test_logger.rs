use slog::{Discard, Logger, o};
use slog_scope::GlobalLoggerGuard;
use std::sync::{Mutex, Once};

static INIT: Once = Once::new();
static GUARD: Mutex<Option<GlobalLoggerGuard>> = Mutex::new(None);

/// Initialise a global slog logger for the whole test binary.
/// Safe to call from every test – the logger is installed exactly once.
pub fn init_test_logger() {
    INIT.call_once(|| {
        let logger = Logger::root(Discard, o!());
        let guard = slog_scope::set_global_logger(logger);
        // Store the guard in a static variable so it stays alive for the entire test run
        *GUARD.lock().unwrap() = Some(guard);
    });
}
