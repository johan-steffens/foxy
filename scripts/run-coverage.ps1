# Foxy API Gateway - Coverage Analysis Script
param(
    [string]$OutputDir = "target/coverage",
    [switch]$OpenReport = $false
)

Write-Host "Running Foxy API Gateway test coverage analysis..." -ForegroundColor Green

# Ensure output directory exists
if (!(Test-Path $OutputDir)) {
    New-Item -ItemType Directory -Path $OutputDir -Force
    Write-Host "Created output directory: $OutputDir" -ForegroundColor Green
}

# Clean previous builds
Write-Host "Cleaning previous builds..." -ForegroundColor Yellow
cargo clean

# Set environment variables for coverage
$env:CARGO_INCREMENTAL = "0"
$env:RUSTFLAGS = "-C instrument-coverage"
$env:LLVM_PROFILE_FILE = "target/coverage/foxy-%p-%m.profraw"

Write-Host "Running tests with coverage instrumentation..." -ForegroundColor Yellow

# Check for cargo-llvm-cov
$llvmCovAvailable = Get-Command "cargo-llvm-cov" -ErrorAction SilentlyContinue

if ($llvmCovAvailable) {
    Write-Host "Using cargo-llvm-cov for coverage analysis..." -ForegroundColor Cyan
    
    & cargo llvm-cov --html --output-dir $OutputDir --ignore-filename-regex "tests/.*"
    
    if ($LASTEXITCODE -eq 0) {
        Write-Host "Coverage analysis completed successfully" -ForegroundColor Green
        $reportPath = Join-Path $OutputDir "index.html"
        
        if ($OpenReport -and (Test-Path $reportPath)) {
            Write-Host "Opening coverage report..." -ForegroundColor Cyan
            Start-Process $reportPath
        }
        
        Write-Host "Coverage report available at: $reportPath" -ForegroundColor Cyan
    } else {
        Write-Host "Error: Coverage analysis failed" -ForegroundColor Red
    }
} else {
    Write-Host "Error: cargo-llvm-cov not found. Please install it first." -ForegroundColor Red
    Write-Host "Run: cargo install cargo-llvm-cov" -ForegroundColor Yellow
    exit 1
}

Write-Host ""
Write-Host "Coverage Analysis Summary:" -ForegroundColor Green
Write-Host "=========================" -ForegroundColor Green

if (Test-Path "$OutputDir/index.html") {
    Write-Host "HTML coverage report generated" -ForegroundColor Green
}

Write-Host ""
Write-Host "Next steps:" -ForegroundColor Cyan
Write-Host "1. Review the coverage report to identify untested code" -ForegroundColor White
Write-Host "2. Add tests for uncovered functions and branches" -ForegroundColor White
Write-Host "3. Focus on error handling and edge cases" -ForegroundColor White
Write-Host "4. Aim for 90 percent line coverage and 80 percent branch coverage" -ForegroundColor White
