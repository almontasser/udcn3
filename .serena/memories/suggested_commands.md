# Essential UDCN Commands

## Build Commands
```bash
# Primary build method (recommended)
./build-all.sh

# Manual build commands
cargo build-ebpf                                    # Build eBPF components first
cargo build --workspace --exclude udcn-ebpf        # Build all workspace packages
cargo build --workspace --exclude udcn-ebpf --release  # Release build
```

## Code Quality Commands
```bash
cargo fmt                    # Format code
cargo clippy --workspace     # Lint code
cargo test --workspace --exclude udcn-ebpf  # Run tests
```

## Development Workflow
```bash
# After making changes:
./build-all.sh                           # Build everything
sudo ./setup-multi-node.sh restart       # Restart all nodes
```

## Network Management
```bash
# Start multi-node network
sudo ./setup-multi-node.sh restart

# Check daemon status
./target/debug/udcn-cli daemon status

# Check network status
./target/debug/udcn-cli network status
```

## File Transfer Operations
```bash
# Send files
./target/debug/udcn-cli send --file /path/to/file --name "/content/name" --target 127.0.0.1:8081

# Receive files
./target/debug/udcn-cli receive --name "/content/name" --output ./received_file --source 127.0.0.1:8080

# With debug logging
RUST_LOG=info ./target/debug/udcn-cli receive --name "/content/name" --output ./received_file --source 127.0.0.1:8080
```

## Benchmarking
```bash
./target/debug/udcn-bench all --duration 30 --output results.json
./target/debug/udcn-bench network throughput
./target/debug/udcn-bench transport quic
```

## System Utilities
Standard Linux commands are available:
- `git` - Version control
- `ls`, `cd`, `pwd` - File navigation
- `grep`, `find` - Text search
- `ps`, `kill` - Process management
- `sudo` - Elevated privileges (required for eBPF)