# UDCN Tech Stack

## Core Technologies
- **Rust**: Primary language (edition 2021, min version 1.90)
- **eBPF**: Kernel-level packet processing using Aya framework
- **Async/Await**: Tokio runtime for asynchronous operations
- **QUIC**: Quinn for transport layer with custom NDN adaptations

## Key Dependencies
- **aya**: eBPF framework for Rust (v0.13.1)
- **aya-ebpf**: eBPF program development
- **tokio**: Async runtime with multi-threading
- **clap**: Command-line argument parsing
- **anyhow**: Error handling
- **log/env_logger**: Logging infrastructure
- **serde**: Serialization/deserialization
- **chrono**: Date/time handling
- **thiserror**: Error type definitions

## Build System
- **Cargo workspace** with multiple crates
- **Cross-compilation** support for Linux targets
- **eBPF build integration** via build scripts
- **LLVM/Clang** for eBPF compilation

## Target Architecture
- Primary: `x86_64-unknown-linux-gnu` 
- eBPF target: `bpfel-unknown-none`
- Cross-compilation: `aarch64-unknown-linux-gnu`
- Requires root privileges for eBPF program loading