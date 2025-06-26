use once_cell::sync::OnceCell;
use slog::{Discard, Logger, o};
use slog_scope::GlobalLoggerGuard;

/// Initialise a global slog logger for the whole test binary.
/// Safe to call from every test – the logger is installed exactly once.
pub fn init_test_logger() {
    static GUARD: OnceCell<GlobalLoggerGuard> = OnceCell::new();

    GUARD.get_or_init(|| {
        let logger = Logger::root(Discard, o!());
        slog_scope::set_global_logger(logger)
    });
}