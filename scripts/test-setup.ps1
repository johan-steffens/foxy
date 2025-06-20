# Foxy API Gateway - Test Setup Script
# This script sets up the testing environment and installs necessary tools

Write-Host "Setting up Foxy API Gateway testing environment..." -ForegroundColor Green

# Check if Rust is installed
if (!(Get-Command "cargo" -ErrorAction SilentlyContinue)) {
    Write-Host "Error: Rust/Cargo not found. Please install Rust first." -ForegroundColor Red
    exit 1
}

Write-Host "Installing code coverage tools..." -ForegroundColor Yellow

# Install cargo-tarpaulin for code coverage
try {
    cargo install cargo-tarpaulin
    Write-Host "✓ cargo-tarpaulin installed successfully" -ForegroundColor Green
} catch {
    Write-Host "Warning: Failed to install cargo-tarpaulin. You may need to install it manually." -ForegroundColor Yellow
}

# Install cargo-llvm-cov as alternative coverage tool
try {
    cargo install cargo-llvm-cov
    Write-Host "✓ cargo-llvm-cov installed successfully" -ForegroundColor Green
} catch {
    Write-Host "Warning: Failed to install cargo-llvm-cov. You may need to install it manually." -ForegroundColor Yellow
}

# Install other useful testing tools
Write-Host "Installing additional testing tools..." -ForegroundColor Yellow

# Install cargo-nextest for faster test execution
try {
    cargo install cargo-nextest
    Write-Host "✓ cargo-nextest installed successfully" -ForegroundColor Green
} catch {
    Write-Host "Warning: Failed to install cargo-nextest." -ForegroundColor Yellow
}

# Install cargo-watch for continuous testing
try {
    cargo install cargo-watch
    Write-Host "✓ cargo-watch installed successfully" -ForegroundColor Green
} catch {
    Write-Host "Warning: Failed to install cargo-watch." -ForegroundColor Yellow
}

# Install cargo-audit for security auditing
try {
    cargo install cargo-audit
    Write-Host "✓ cargo-audit installed successfully" -ForegroundColor Green
} catch {
    Write-Host "Warning: Failed to install cargo-audit." -ForegroundColor Yellow
}

Write-Host "Creating test directories..." -ForegroundColor Yellow

# Create test directories
$testDirs = @(
    "tests",
    "tests/integration",
    "tests/fixtures",
    "tests/mocks",
    "benches"
)

foreach ($dir in $testDirs) {
    if (!(Test-Path $dir)) {
        New-Item -ItemType Directory -Path $dir -Force
        Write-Host "✓ Created directory: $dir" -ForegroundColor Green
    }
}

Write-Host "Setting up test configuration files..." -ForegroundColor Yellow

# Create .cargo/config.toml for test configuration
if (!(Test-Path ".cargo")) {
    New-Item -ItemType Directory -Path ".cargo" -Force
}

$cargoConfig = @"
[env]
RUST_LOG = "debug"
RUST_BACKTRACE = "1"

[target.'cfg(all())']
rustflags = ["-C", "instrument-coverage"]

[build]
rustflags = ["-C", "instrument-coverage"]
"@

$cargoConfig | Out-File -FilePath ".cargo/config.toml" -Encoding UTF8
Write-Host "✓ Created .cargo/config.toml" -ForegroundColor Green

Write-Host "Test environment setup complete!" -ForegroundColor Green
Write-Host ""
Write-Host "Available commands:" -ForegroundColor Cyan
Write-Host "  cargo test                    - Run all tests" -ForegroundColor White
Write-Host "  cargo tarpaulin --out Html    - Generate HTML coverage report" -ForegroundColor White
Write-Host "  cargo llvm-cov --html         - Alternative coverage report" -ForegroundColor White
Write-Host "  cargo nextest run             - Fast test execution" -ForegroundColor White
Write-Host "  cargo watch -x test           - Continuous testing" -ForegroundColor White
Write-Host "  cargo bench                   - Run benchmarks" -ForegroundColor White
