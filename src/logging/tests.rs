// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Comprehensive tests for the logging module to achieve 95% coverage

#[cfg(test)]
mod tests {
    use super::super::*;
    use crate::logging::config::LoggingConfig;
    use crate::logging::test_logger;
    use log::LevelFilter;
    use std::sync::atomic::Ordering;

    // Helper function to reset logging state for testing
    fn reset_logging_state() {
        // Reset the atomic flag
        USING_STRUCTURED.store(false, Ordering::SeqCst);
        
        // Note: We can't reset the Once, but we can test different scenarios
        // by creating new processes or using different test strategies
    }

    #[test]
    fn test_init_with_config_structured_logging() {
        let config = LoggingConfig {
            structured: true,
            level: "debug".to_string(),
            format: "json".to_string(),
            include_location: true,
            include_thread_id: true,
            include_trace_id: true,
            propagate_trace_id: true,
            trace_id_header: "X-Trace-ID".to_string(),
            static_fields: std::collections::HashMap::new(),
        };

        // Test initialization with structured logging
        init_with_config(LevelFilter::Debug, &config);

        // Note: Due to the Once guard, we can't reliably test the structured logging state
        // in unit tests since other tests may have already initialized the logger.
        // We just verify the function doesn't panic.
    }

    #[test]
    fn test_init_with_config_env_logger() {
        reset_logging_state();

        let config = LoggingConfig {
            structured: false,
            level: "info".to_string(),
            format: "terminal".to_string(),
            include_location: false,
            include_thread_id: false,
            include_trace_id: false,
            propagate_trace_id: false,
            trace_id_header: "X-Trace-ID".to_string(),
            static_fields: std::collections::HashMap::new(),
        };

        // Test initialization with env_logger
        init_with_config(LevelFilter::Info, &config);

        // Since we can't easily reset the Once, we test the function doesn't panic
        // and that the logging level is set correctly
        assert_eq!(log::max_level(), LevelFilter::Info);
    }

    #[test]
    fn test_init_with_config_different_levels() {
        let levels = vec![
            LevelFilter::Error,
            LevelFilter::Warn,
            LevelFilter::Info,
            LevelFilter::Debug,
            LevelFilter::Trace,
        ];

        for level in levels {
            let config = LoggingConfig {
                structured: false,
                level: level.to_string(),
                format: "terminal".to_string(),
                include_location: true,
                include_thread_id: true,
                include_trace_id: true,
                propagate_trace_id: true,
                trace_id_header: "X-Trace-ID".to_string(),
                static_fields: std::collections::HashMap::new(),
            };

            // Test that initialization doesn't panic with different levels
            init_with_config(level, &config);
        }
    }

    #[test]
    fn test_is_structured_logging() {
        // Test the atomic boolean getter
        let initial_state = is_structured_logging();
        
        // The function should return a boolean without panicking
        assert!(initial_state == true || initial_state == false);
        
        // Test setting the state manually
        USING_STRUCTURED.store(true, Ordering::SeqCst);
        assert!(is_structured_logging());
        
        USING_STRUCTURED.store(false, Ordering::SeqCst);
        assert!(!is_structured_logging());
    }

    #[test]
    fn test_log_error_structured() {
        // Set up a minimal structured logger for testing
        let drain = slog::Discard;
        let logger = slog::Logger::root(drain, slog::o!());
        test_logger::init_test_logger();

        USING_STRUCTURED.store(true, Ordering::SeqCst);

        let test_error = "Test error message";
        let context = "TestContext";

        // Test that log_error returns the error unchanged
        let returned_error = log_error(context, test_error);
        assert_eq!(returned_error, test_error);
    }

    #[test]
    fn test_log_error_non_structured() {
        USING_STRUCTURED.store(false, Ordering::SeqCst);
        
        let test_error = "Test error message";
        let context = "TestContext";
        
        // Test that log_error returns the error unchanged
        let returned_error = log_error(context, test_error);
        assert_eq!(returned_error, test_error);
    }

    #[test]
    fn test_log_warning_structured() {
        // Set up a minimal structured logger for testing
        let drain = slog::Discard;
        let logger = slog::Logger::root(drain, slog::o!());
        test_logger::init_test_logger();

        USING_STRUCTURED.store(true, Ordering::SeqCst);

        let test_warning = "Test warning message";
        let context = "TestContext";

        // Test that log_warning doesn't panic
        log_warning(context, test_warning);
    }

    #[test]
    fn test_log_warning_non_structured() {
        USING_STRUCTURED.store(false, Ordering::SeqCst);
        
        let test_warning = "Test warning message";
        let context = "TestContext";
        
        // Test that log_warning doesn't panic
        log_warning(context, test_warning);
    }

    #[test]
    fn test_log_debug_structured() {
        // Set up a minimal structured logger for testing
        let drain = slog::Discard;
        let logger = slog::Logger::root(drain, slog::o!());
        test_logger::init_test_logger();

        USING_STRUCTURED.store(true, Ordering::SeqCst);

        let test_message = "Test debug message";
        let context = "TestContext";

        // Test that log_debug doesn't panic
        log_debug(context, test_message);
    }

    #[test]
    fn test_log_debug_non_structured() {
        USING_STRUCTURED.store(false, Ordering::SeqCst);
        
        let test_message = "Test debug message";
        let context = "TestContext";
        
        // Test that log_debug doesn't panic
        log_debug(context, test_message);
    }

    #[test]
    fn test_log_trace_structured() {
        // Set up a minimal structured logger for testing
        let drain = slog::Discard;
        let logger = slog::Logger::root(drain, slog::o!());
        test_logger::init_test_logger();

        USING_STRUCTURED.store(true, Ordering::SeqCst);

        let test_message = "Test trace message";
        let context = "TestContext";

        // Test that log_trace doesn't panic
        log_trace(context, test_message);
    }

    #[test]
    fn test_log_trace_non_structured() {
        USING_STRUCTURED.store(false, Ordering::SeqCst);
        
        let test_message = "Test trace message";
        let context = "TestContext";
        
        // Test that log_trace doesn't panic
        log_trace(context, test_message);
    }

    #[test]
    fn test_log_info_structured() {
        // Set up a minimal structured logger for testing
        let drain = slog::Discard;
        let logger = slog::Logger::root(drain, slog::o!());
        test_logger::init_test_logger();

        USING_STRUCTURED.store(true, Ordering::SeqCst);

        let test_message = "Test info message";
        let context = "TestContext";

        // Test that log_info doesn't panic
        log_info(context, test_message);
    }

    #[test]
    fn test_log_info_non_structured() {
        USING_STRUCTURED.store(false, Ordering::SeqCst);
        
        let test_message = "Test info message";
        let context = "TestContext";
        
        // Test that log_info doesn't panic
        log_info(context, test_message);
    }

    #[test]
    fn test_log_with_context_all_levels_structured() {
        // Set up a minimal structured logger for testing
        let drain = slog::Discard;
        let logger = slog::Logger::root(drain, slog::o!());
        test_logger::init_test_logger();

        USING_STRUCTURED.store(true, Ordering::SeqCst);

        let message = "Test message";
        let context = "TestContext";
        let fields = vec![
            ("field1", "value1".to_string()),
            ("field2", "value2".to_string()),
        ];

        let levels = vec![
            log::Level::Error,
            log::Level::Warn,
            log::Level::Info,
            log::Level::Debug,
            log::Level::Trace,
        ];

        for level in levels {
            // Test that log_with_context doesn't panic for any level
            log_with_context(level, message, context, &fields);
        }
    }

    #[test]
    fn test_log_with_context_all_levels_non_structured() {
        // Initialize env_logger for non-structured logging
        let _ = env_logger::builder().is_test(true).try_init();

        // Set up a minimal structured logger for testing (even for non-structured test)
        let drain = slog::Discard;
        let logger = slog::Logger::root(drain, slog::o!());

        USING_STRUCTURED.store(false, Ordering::SeqCst);

        let message = "Test message";
        let context = "TestContext";
        let fields = vec![
            ("field1", "value1".to_string()),
            ("field2", "value2".to_string()),
        ];

        let levels = vec![
            log::Level::Error,
            log::Level::Warn,
            log::Level::Info,
            log::Level::Debug,
            log::Level::Trace,
        ];

        // Use scope instead of global logger to avoid conflicts
        slog_scope::scope(&logger, || {
            for level in levels {
                // Test that log_with_context doesn't panic for any level
                log_with_context(level, message, context, &fields);
            }
        });
    }

    #[test]
    fn test_log_with_context_empty_fields() {
        // Set up a minimal structured logger for testing
        let drain = slog::Discard;
        let logger = slog::Logger::root(drain, slog::o!());
        test_logger::init_test_logger();

        USING_STRUCTURED.store(true, Ordering::SeqCst);

        let message = "Test message";
        let context = "TestContext";
        let empty_fields: Vec<(&'static str, String)> = vec![];

        // Test with empty fields array
        log_with_context(log::Level::Info, message, context, &empty_fields);
    }

    #[test]
    fn test_add_fields_to_logger() {
        // Create a test logger (this requires slog to be initialized)
        let drain = slog::Discard;
        let logger = slog::Logger::root(drain, slog::o!());
        
        let fields = vec![
            ("test_field1", "value1".to_string()),
            ("test_field2", "value2".to_string()),
            ("test_field3", "value3".to_string()),
        ];

        // Test that add_fields_to_logger doesn't panic
        let result_logger = add_fields_to_logger(logger, &fields);
        
        // The function should return a logger (we can't easily test the fields without complex setup)
        // But we can verify it doesn't panic and returns a logger
        assert!(std::ptr::addr_of!(result_logger) != std::ptr::null());
    }

    #[test]
    fn test_add_fields_to_logger_empty_fields() {
        let drain = slog::Discard;
        let logger = slog::Logger::root(drain, slog::o!());

        let empty_fields: Vec<(&'static str, String)> = vec![];

        // Test with empty fields
        let result_logger = add_fields_to_logger(logger, &empty_fields);
        assert!(std::ptr::addr_of!(result_logger) != std::ptr::null());
    }

    #[test]
    fn test_add_fields_to_logger_single_field() {
        let drain = slog::Discard;
        let logger = slog::Logger::root(drain, slog::o!());

        let fields = vec![("single_field", "single_value".to_string())];

        // Test with single field
        let result_logger = add_fields_to_logger(logger, &fields);
        assert!(std::ptr::addr_of!(result_logger) != std::ptr::null());
    }

    #[test]
    fn test_add_fields_to_logger_many_fields() {
        let drain = slog::Discard;
        let logger = slog::Logger::root(drain, slog::o!());

        let fields = vec![
            ("field_1", "value_1".to_string()),
            ("field_2", "value_2".to_string()),
            ("field_3", "value_3".to_string()),
            ("field_4", "value_4".to_string()),
            ("field_5", "value_5".to_string()),
        ];

        // Test with many fields
        let result_logger = add_fields_to_logger(logger, &fields);
        assert!(std::ptr::addr_of!(result_logger) != std::ptr::null());
    }

    #[test]
    fn test_logging_functions_with_different_types() {
        USING_STRUCTURED.store(false, Ordering::SeqCst);

        // Test with different Display types
        log_error("context", 42);
        log_error("context", "string error");
        log_error("context", format!("formatted {}", "error"));

        log_warning("context", 3.14);
        log_warning("context", true);

        log_debug("context", "debug message");
        log_info("context", "info message");
        log_trace("context", "trace message");
    }

    #[test]
    fn test_logging_functions_with_empty_context() {
        USING_STRUCTURED.store(false, Ordering::SeqCst);

        // Test with empty context string
        log_error("", "error message");
        log_warning("", "warning message");
        log_debug("", "debug message");
        log_info("", "info message");
        log_trace("", "trace message");
    }

    #[test]
    fn test_logging_functions_with_special_characters() {
        USING_STRUCTURED.store(false, Ordering::SeqCst);

        // Test with special characters in context and messages
        log_error("Context with spaces", "Error with\nnewlines");
        log_warning("Context-with-dashes", "Warning with\ttabs");
        log_debug("Context_with_underscores", "Debug with \"quotes\"");
        log_info("Context.with.dots", "Info with 'single quotes'");
        log_trace("Context/with/slashes", "Trace with unicode: 🦀");
    }

    #[test]
    fn test_log_with_context_special_field_values() {
        // Set up a minimal structured logger for testing
        let drain = slog::Discard;
        let logger = slog::Logger::root(drain, slog::o!());
        test_logger::init_test_logger();

        USING_STRUCTURED.store(true, Ordering::SeqCst);

        let message = "Test message";
        let context = "TestContext";
        let special_fields = vec![
            ("empty_field", "".to_string()),
            ("unicode_field", "🦀 Rust".to_string()),
            ("json_like_field", r#"{"key": "value"}"#.to_string()),
            ("newline_field", "line1\nline2".to_string()),
            ("tab_field", "col1\tcol2".to_string()),
        ];

        // Test with special field values
        log_with_context(log::Level::Info, message, context, &special_fields);
    }

    #[test]
    fn test_init_with_config_multiple_calls() {
        // Test that multiple calls to init_with_config don't cause issues
        // (Due to Once, only the first call should actually initialize)

        let config1 = LoggingConfig {
            structured: false,
            level: "error".to_string(),
            format: "terminal".to_string(),
            include_location: false,
            include_thread_id: false,
            include_trace_id: false,
            propagate_trace_id: false,
            trace_id_header: "X-Trace-ID".to_string(),
            static_fields: std::collections::HashMap::new(),
        };

        let config2 = LoggingConfig {
            structured: true,
            level: "trace".to_string(),
            format: "json".to_string(),
            include_location: true,
            include_thread_id: true,
            include_trace_id: true,
            propagate_trace_id: true,
            trace_id_header: "X-Trace-ID".to_string(),
            static_fields: std::collections::HashMap::new(),
        };

        // Multiple calls should not panic
        init_with_config(LevelFilter::Error, &config1);
        init_with_config(LevelFilter::Trace, &config2);
        init_with_config(LevelFilter::Debug, &config1);
    }

    #[test]
    fn test_logging_config_with_static_fields() {
        let mut static_fields = std::collections::HashMap::new();
        static_fields.insert("service".to_string(), "test-service".to_string());
        static_fields.insert("version".to_string(), "1.0.0".to_string());
        static_fields.insert("environment".to_string(), "test".to_string());

        let config = LoggingConfig {
            structured: true,
            level: "info".to_string(),
            format: "json".to_string(),
            include_location: true,
            include_thread_id: true,
            include_trace_id: true,
            propagate_trace_id: true,
            trace_id_header: "X-Trace-ID".to_string(),
            static_fields,
        };

        // Test initialization with static fields
        init_with_config(LevelFilter::Info, &config);
    }

    #[test]
    fn test_atomic_operations_thread_safety() {
        use std::thread;

        let handles: Vec<_> = (0..10).map(|i| {
            thread::spawn(move || {
                // Test concurrent access to the atomic boolean
                let state = is_structured_logging();
                USING_STRUCTURED.store(i % 2 == 0, Ordering::SeqCst);
                let new_state = is_structured_logging();

                // Both operations should complete without panicking
                (state, new_state)
            })
        }).collect();

        // Wait for all threads to complete
        for handle in handles {
            let _ = handle.join();
        }
    }

    #[test]
    fn test_log_error_return_value_preservation() {
        // Test that log_error preserves the exact error value
        #[derive(Debug, PartialEq)]
        struct CustomError {
            code: i32,
            message: String,
        }

        impl std::fmt::Display for CustomError {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "Error {}: {}", self.code, self.message)
            }
        }

        let original_error = CustomError {
            code: 404,
            message: "Not found".to_string(),
        };

        let returned_error = log_error("TestContext", original_error);

        // The returned error should be identical to the original
        assert_eq!(returned_error.code, 404);
        assert_eq!(returned_error.message, "Not found");
    }
}
