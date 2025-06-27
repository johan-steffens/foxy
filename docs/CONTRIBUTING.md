# Contributing to Foxy

We welcome contributions to Foxy! This guide will help you get started and understand our development workflow, coding style, and best practices.

## Table of Contents

1.  [Getting Started](#getting-started)
2.  [Project Structure](#project-structure)
3.  [Development Workflow](#development-workflow)
4.  [Code Style and Quality](#code-style-and-quality)
5.  [Testing](#testing)
6.  [Documentation](#documentation)
7.  [Submitting Changes](#submitting-changes)

## 1. Getting Started

Before you begin, ensure you have the Rust toolchain installed. We recommend using `rustup` for managing Rust versions.

*   **Install `rustup`**:
    ```bash
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
    ```
*   **Install `rustfmt` and `clippy`**:
    ```bash
    rustup component add rustfmt clippy
    ```
*   **Clone the repository**:
    ```bash
    git clone https://github.com/johansteffens/foxy.git
    cd foxy
    ```

## 2. Project Structure

Foxy follows a standard Rust project layout:

*   `src/`: Contains the main source code for the `foxy` library and binary.
    *   `src/lib.rs`: The main library entry point.
    *   `src/bin/foxy.rs`: The main binary application.
    *   `src/config/`: Configuration handling.
    *   `src/core/`: Core application logic.
    *   `src/filters/`: Request filtering logic.
    *   `src/loader/`: Dynamic loading mechanisms.
    *   `src/logging/`: Logging infrastructure.
    *   `src/opentelemetry/`: OpenTelemetry integration.
    *   `src/router/`: Request routing.
    *   `src/security/`: Security-related features (e.g., OIDC, Basic Auth).
    *   `src/server/`: HTTP server setup and health checks.
*   `tests/`: Contains integration and end-to-end tests.
*   `config/`: Default and example configuration files.
*   `docs/`: Project documentation, including this guide.
*   `.github/workflows/`: GitHub Actions CI/CD configurations.
*   `Cargo.toml`: Project manifest and dependency definitions.
*   `Cargo.lock`: Exact dependency versions.

## 3. Development Workflow

We use a feature-branch workflow and pull requests for all contributions.

1.  **Fork the repository** on GitHub.
2.  **Create a new branch** from `main` for your feature or bug fix:
    ```bash
    git checkout main
    git pull origin main
    git checkout -b feature/your-feature-name
    ```
    (or `bugfix/your-bug-name` for bug fixes)
3.  **Make your changes**.
4.  **Commit your changes** with clear and concise commit messages. Follow the [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/) specification (e.g., `feat: add new routing capability`, `fix: resolve memory leak in logger`).
5.  **Push your branch** to your fork.
6.  **Open a Pull Request** to the `develop` branch of the original repository. This will kick off test and audit workflows that are required to pass as part of the PR process.

## 4. Code Style and Quality

We enforce consistent code style and high code quality using `rustfmt` and `clippy`.

*   **Formatting**: Always run `rustfmt` before committing your changes.
    ```bash
    cargo fmt --all
    ```
*   **Linting**: Always run `clippy` to catch common mistakes and improve your code. Address all warnings.
    ```bash
    cargo clippy --all-targets -- -D warnings
    ```
    The `-- -D warnings` flag treats all warnings as errors, ensuring a clean linting pass.
*   **Rust Principles**:
    *   **Ownership and Borrowing**: Understand and correctly apply Rust's ownership system to prevent data races and ensure memory safety. Prefer immutable references (`&T`) over mutable ones (`&mut T`) when possible.
    *   **Error Handling**: Use `Result<T, E>` for recoverable errors and `panic!` for unrecoverable errors or programmer mistakes. Avoid `unwrap()` and `expect()` in production code; use `?` operator or `match` statements for proper error propagation.
    *   **Modularity**: Organize code into logical modules and crates.
    *   **Performance**: Be mindful of performance-critical sections, but prioritize correctness and readability first.
    *   **Safety**: Write `unsafe` code only when absolutely necessary and with extreme caution, providing clear justifications and invariants.

## 5. Testing

All new features and bug fixes should be accompanied by appropriate tests.

*   **Run all tests**:
    ```bash
    cargo test
    ```
*   **Run unit tests for a specific module**:
    ```bash
    cargo test --package foxy --lib -- src/module_name::tests
    ```
*   **Run integration tests**: Integration tests are located in the `tests/` directory.
    ```bash
    cargo test --test binary_integration
    ```
    To run all integration tests:
    ```bash
    cargo test --workspace --exclude foxy --tests
    ```
    Note: Some integration tests might require specific environment setups or external services. Refer to the test files for details.
*   **Adding new tests**:
    *   **Unit tests**: Place them in a `tests` module within the same file as the code they test, marked with `#[cfg(test)]`.
    *   **Integration tests**: Create new files in the `tests/` directory.

## 6. Documentation

Good documentation is crucial for maintainability and usability.

*   **Doc Comments**: Use `///` for documentation comments on public items (functions, structs, enums, traits, modules).
    ```rust
    /// Calculates the sum of two numbers.
    ///
    /// # Arguments
    ///
    /// * `a` - The first number.
    /// * `b` - The second number.
    ///
    /// # Examples
    ///
    /// ```
    /// let result = foxy::add(1, 2);
    /// assert_eq!(result, 3);
    /// ```
    pub fn add(a: i32, b: i32) -> i32 {
        a + b
    }
    ```
*   **Markdown Files**: Update or create new Markdown files in the `docs/` directory for broader architectural or conceptual documentation.

## 7. Submitting Changes

Once you're ready to submit your changes:

1.  Ensure all tests pass locally (`cargo test`).
2.  Ensure `cargo fmt --all` and `cargo clippy --all-targets -- -D warnings` run without issues.
3.  Push your branch to your fork.
4.  Open a Pull Request on GitHub targeting the `develop` branch. This will kick off test and audit workflows that are required to pass as part of the PR process.
5.  Provide a clear description of your changes, including why they are needed and what problem they solve. Reference any related issues.
6.  Be responsive to feedback during the code review process.

Thank you for contributing to Foxy!