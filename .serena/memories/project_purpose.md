# UDCN Project Purpose

uDCN is a **Micro Data Centric Networking** project implemented in Rust that combines:

## Core Functionality
- **eBPF-based packet processing** using the Aya framework for high-performance network filtering
- **NDN (Named Data Networking)** protocol implementation with custom transport layers
- **Content-based networking** with hierarchical naming and content routing
- **QUIC transport** with NDN-specific optimizations and multiplexing
- **File transfer capabilities** with chunking, reassembly, and integrity verification

## Key Components
- **udcn**: Main eBPF program that attaches to network interfaces (XDP)
- **udcn-core**: Core NDN protocol implementation (TLV encoding, signatures, packets)
- **udcn-transport**: Transport layer abstractions (TCP, UDP, QUIC, Unix sockets)
- **udcn-cli**: Command-line interface for the system
- **udcn-daemon**: Background service daemon
- **udcn-bench**: Benchmarking and performance testing tools
- **udcn-ebpf**: eBPF programs for packet filtering and NDN processing

## Technical Architecture
The project uses eBPF for kernel-level packet processing with NDN interest/data packet recognition and filtering, combined with userspace components for higher-level protocol handling and application interfaces.
