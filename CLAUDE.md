# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build Commands

**Primary build method:**
```bash
./build-all.sh
```

**Manual build commands:**
```bash
# Build eBPF components first
cargo build-ebpf

# Build all workspace packages (excluding eBPF)
cargo build --workspace --exclude udcn-ebpf

# Release build
cargo build --workspace --exclude udcn-ebpf --release
```

**Format and lint:**
```bash
cargo fmt
cargo clippy --workspace
```

**Test commands:**
```bash
cargo test --workspace --exclude udcn-ebpf
```

## Project Architecture

UDCN is a high-performance Named Data Networking (NDN) implementation with eBPF acceleration. The project is structured as a Rust workspace with multiple packages:

### Core Packages
- **`udcn`** - Main eBPF XDP program for packet-level processing
- **`udcnd`** - UDCN daemon (NDN forwarder/router) - the main networking service
- **`udcn-cli`** - Command-line interface for file transfers and network management
- **`udcn-bench`** - Performance testing and topology simulation tool

### Library Packages
- **`udcn-core`** - Core NDN protocol implementation (packets, names, signatures, TLV)
- **`udcn-transport`** - Transport layer implementations (TCP, UDP, UNIX, QUIC) with NDN optimizations
- **`udcn-common`** - Shared utilities and common code
- **`udcn-ebpf`** - eBPF programs (requires special build profile)

### Key Components

**Daemon Architecture (`udcnd`):**
- `daemon.rs` - Main daemon orchestrator
- `face_manager.rs` - Network face management
- `routing.rs` - NDN routing strategies
- `transport_manager.rs` - Multi-protocol transport handling
- `control_plane.rs` - Control plane management
- `packet_handler.rs` - NDN packet processing

**Transport Layer (`udcn-transport`):**
- Multiple transport protocols: TCP, UDP, UNIX sockets, QUIC
- NDN-specific optimizations and forwarding
- File chunking and reassembly for large transfers
- Progress tracking and pipeline coordination

**Core Protocol (`udcn-core`):**
- NDN packet types (Interest, Data)
- Name processing and hierarchical naming
- Security and signature handling
- TLV (Type-Length-Value) encoding

## Development Setup

**Prerequisites:**
- Rust nightly toolchain (configured in `rust-toolchain.toml`)
- `bpf-linker` for eBPF compilation: `cargo install bpf-linker`
- Linux with eBPF support (root required for eBPF operations)

**Configuration files:**
- `config/node1.conf` - Primary node (127.0.0.1:8080)
- `config/node2.conf` - Secondary node (127.0.0.1:8081) 
- `config/node3.conf` - Tertiary node (127.0.0.1:8082)

## Running the System

**Start multi-node network:**
```bash
sudo ./setup-multi-node.sh restart
```

**CLI operations:**
```bash
# Send files
./target/release/udcn-cli send --file /path/to/file --name "/content/name" --target 127.0.0.1:8081

# Receive files  
./target/release/udcn-cli receive --name "/content/name" --output ./received_file --source 127.0.0.1:8080

# Receive files with progress and debug logs
RUST_LOG=info ./target/release/udcn-cli receive --name "/content/name" --output ./received_file --source 127.0.0.1:8080

# Network status
./target/release/udcn-cli network status
```

# Correct Workflow For Development
After changing code, we execute ./build-all.sh, then restart the nodes with the command `sudo ./setup-multi-node.sh restart`.

# Notes
The argument --help does not work for udcn-cli

## Code Style

- Uses nightly Rust with specific rustfmt configuration
- Import grouping: StdExternalCrate
- eBPF code requires special build profiles with debug info
- All workspace packages follow unified dependency management
