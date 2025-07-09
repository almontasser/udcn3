# UDCN Suggested Commands

## Build Commands
```bash
# Build all workspace packages (excluding eBPF)
cargo build --workspace --exclude udcn-ebpf

# Build eBPF programs specifically
cargo build-ebpf

# Build everything (convenience script)
./build-all.sh

# Release build
cargo build-release
```

## Testing Commands
```bash
# Run all tests in workspace
cargo test-all

# Run tests with all features
cargo test --workspace --all-targets --all-features

# Run specific package tests
cargo test --package udcn-core
```

## Code Quality Commands
```bash
# Format all code
cargo fmt-all

# Run clippy linting
cargo clippy-all

# Check all packages
cargo check-all
```

## Running the Application
```bash
# Run main UDCN program (requires root for eBPF)
cargo run --release --config 'target."cfg(all())".runner="sudo -E"'

# Run with specific interface (default is eth0)
cargo run --release --config 'target."cfg(all())".runner="sudo -E"' -- --iface=wlan0

# Run CLI tool
cargo run --package udcn-cli

# Run daemon
cargo run --package udcnd

# Run benchmarks
cargo run --package udcn-bench
```

## Development Commands
```bash
# Check code without building
cargo check

# Run benchmarks
cargo bench-all

# Clean build artifacts
cargo clean
```