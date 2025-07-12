# UDCN Architecture

## Workspace Structure
UDCN is organized as a Rust workspace with multiple specialized packages:

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

## Daemon Architecture (`udcnd`)
- `daemon.rs` - Main daemon orchestrator
- `face_manager.rs` - Network face management
- `routing.rs` - NDN routing strategies
- `transport_manager.rs` - Multi-protocol transport handling
- `control_plane.rs` - Control plane management
- `packet_handler.rs` - NDN packet processing

## Transport Layer (`udcn-transport`)
- Multiple transport protocols: TCP, UDP, UNIX sockets, QUIC
- NDN-specific optimizations and forwarding
- File chunking and reassembly for large transfers
- Progress tracking and pipeline coordination
- Stream multiplexing and connection pooling

## Core Protocol (`udcn-core`)
- NDN packet types (Interest, Data)
- Name processing and hierarchical naming
- Security and signature handling
- TLV (Type-Length-Value) encoding