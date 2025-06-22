# Coverage Workflow

The Foxy project includes a separate, optional coverage workflow that can be run manually or automatically on code changes.

## Running Coverage

### Manual Execution
1. Go to the **Actions** tab in GitHub
2. Select **Coverage Report** workflow
3. Click **Run workflow**
4. Choose whether to upload to Codecov (default: true)

### Automatic Execution
The workflow automatically runs on:
- Pushes to `main` branch
- Changes to source code (`src/**`, `tests/**`, `Cargo.toml`, `Cargo.lock`)

## Codecov Integration

### Setup
To enable Codecov uploads, add your Codecov token as a repository secret:
1. Go to **Settings** → **Secrets and variables** → **Actions**
2. Add a new secret named `CODECOV_TOKEN`
3. Set the value to your Codecov project token

### Without Token
If no Codecov token is configured:
- Coverage reports are still generated
- HTML reports are available as workflow artifacts
- Codecov upload is gracefully skipped with a warning

## Output

The workflow generates:
- **HTML Report**: Interactive coverage report (downloadable artifact)
- **LCOV Report**: Machine-readable format for Codecov
- **JSON Report**: Structured data for programmatic use
- **Summary**: Coverage percentage in workflow summary

## Local Coverage

To run coverage locally:

```bash
# Install coverage tools
cargo install cargo-llvm-cov

# Generate HTML report
cargo llvm-cov --html --output-dir coverage

# Generate LCOV report
cargo llvm-cov --lcov --output-path coverage.lcov

# Open HTML report
open coverage/index.html  # macOS
xdg-open coverage/index.html  # Linux
```

## Benefits

- **Simplified CI**: Main CI pipeline focuses on core testing
- **Optional Coverage**: Run coverage analysis when needed
- **Flexible**: Manual or automatic execution
- **Comprehensive**: Multiple output formats
- **Robust**: Graceful handling of missing tokens
