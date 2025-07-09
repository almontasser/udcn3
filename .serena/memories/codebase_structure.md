# UDCN Codebase Structure

## Workspace Layout
```
udcn/
├── udcn/              # Main eBPF application
├── udcn-common/       # Shared types and constants
├── udcn-core/         # Core NDN protocol implementation
├── udcn-transport/    # Transport layer abstractions
├── udcn-cli/          # Command-line interface
├── udcnd/             # Background daemon
├── udcn-bench/        # Benchmarking tools
├── udcn-ebpf/         # eBPF programs
├── examples/          # Example code
└── .taskmaster/       # Task Master AI project management
```

## Key Modules

### udcn-core
- **name.rs**: Name processing, hierarchies, validation
- **packets.rs**: NDN packet structures (Interest, Data)
- **tlv.rs**: TLV encoding/decoding
- **signature.rs**: Cryptographic signatures
- **security.rs**: Security context management
- **network.rs**: Network node abstraction

### udcn-transport
- **tcp.rs, udp.rs, unix.rs**: Basic transport implementations
- **quic.rs**: QUIC transport with NDN optimizations
- **ndn_quic.rs**: NDN-specific QUIC framing
- **file_*.rs**: File transfer modules (chunking, reassembly, integrity)
- **ndn_*.rs**: NDN-specific optimizations and forwarding

### udcn-ebpf
- **main.rs**: XDP program for packet filtering and NDN processing
- Maps: CONFIG_MAP, FILTER_RULES, PACKET_STATS, INTEREST_CACHE

## Build Integration
- **build.rs**: Build scripts for eBPF integration
- **Cargo.toml**: Workspace configuration with profiles
- **.cargo/config.toml**: Build aliases and target configuration