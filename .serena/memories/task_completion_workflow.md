# Task Completion Workflow

## Standard Development Workflow
When completing any coding task, follow these steps:

### 1. Code Changes
Make your changes to the relevant source files.

### 2. Build and Validate
```bash
# Format code (required)
cargo fmt

# Build everything
./build-all.sh

# Run linting (recommended)
cargo clippy --workspace

# Run tests (if applicable)
cargo test --workspace --exclude udcn-ebpf
```

### 3. System Testing
For changes affecting the daemon or transport layers:
```bash
# Restart the multi-node network
sudo ./setup-multi-node.sh restart

# Test basic functionality
./target/debug/udcn-cli network status
```

### 4. Integration Testing
For file transfer or protocol changes:
```bash
# Test file sending
echo "test content" > test.txt
./target/debug/udcn-cli send --file test.txt --name "/test/file" --target 127.0.0.1:8081

# Test file receiving
./target/debug/udcn-cli receive --name "/test/file" --output received.txt --source 127.0.0.1:8080
```

## Important Notes
- **Always format code** with `cargo fmt` before completion
- **Build must succeed** - fix all compilation errors and warnings
- **Test networking changes** by restarting nodes and verifying functionality
- **Use debug logging** (`RUST_LOG=debug`) to troubleshoot issues
- **Root privileges required** for eBPF operations and some network tests

## Critical Requirements
- Code must compile without errors
- All formatting must be applied
- Basic functionality must be verified after changes
- Follow the import grouping style (StdExternalCrate)