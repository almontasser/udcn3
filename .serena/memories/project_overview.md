# UDCN Project Overview

## Purpose
UDCN (Userland Defined Compute Network) is a high-performance Named Data Networking (NDN) implementation with eBPF acceleration for content-centric networking and file distribution.

## Key Features
- **Named Data Networking**: Content-centric addressing with automatic caching
- **eBPF Acceleration**: High-performance packet processing with XDP  
- **Multi-transport**: Support for UDP, TCP, Unix sockets, and QUIC
- **Content Caching**: Built-in content store with configurable size limits
- **Interest Aggregation**: Efficient handling of duplicate requests
- **Network Discovery**: Automatic peer discovery and health monitoring
- **File Chunking**: Efficient large file transfer with integrity checking
- **Performance Monitoring**: Comprehensive benchmarking and statistics

## Technology Stack
- **Language**: Rust (nightly toolchain)
- **Networking**: eBPF/XDP, QUIC (Quinn), TCP, UDP, Unix sockets
- **Async Runtime**: Tokio
- **Build System**: Cargo workspace
- **eBPF Framework**: Aya
- **TLS**: rustls
- **Serialization**: serde, serde_json
- **Logging**: tracing, log
- **CLI**: clap

## System Requirements
- Linux kernel with eBPF support
- Root privileges for eBPF operations
- Rust nightly toolchain
- bpf-linker for eBPF compilation