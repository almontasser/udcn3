# UDCN - Userland Defined Compute Network

A high-performance Named Data Networking (NDN) implementation with eBPF acceleration for content-centric networking and file distribution.

## Prerequisites

1. **Rust toolchains:**
   - Stable: `rustup toolchain install stable`
   - Nightly: `rustup toolchain install nightly --component rust-src`
   - bpf-linker: `cargo install bpf-linker` (`--no-default-features` on macOS)

2. **System requirements:**
   - Linux kernel with eBPF support (requires root for eBPF operations)
   - Network interface access

3. **Cross-compiling (optional):**
   - Target: `rustup target add ${ARCH}-unknown-linux-musl`
   - LLVM: `brew install llvm` (macOS)
   - C toolchain: `brew install filosottile/musl-cross/musl-cross` (macOS)

## Build Instructions

### Quick Build
```bash
./build-all.sh
```

### Manual Build
```bash
# Build eBPF components
cargo build-ebpf

# Build all workspace packages
cargo build --workspace --exclude udcn-ebpf --release
```

## Available Programs

After building, you'll have these executables in `target/release/`:

- **`udcn`** - eBPF XDP program for packet-level processing
- **`udcnd`** - UDCN daemon (NDN forwarder/router)
- **`udcn-cli`** - Command-line interface for file transfers and network management
- **`udcn-bench`** - Performance testing and topology simulation tool

## Network Setup

### 1. Start UDCN Daemons

Start multiple nodes to create an NDN network:

```bash
# Node 1 (Primary - Port 8080)
sudo ./target/release/udcnd -c config/node1.conf -d

# Node 2 (Secondary - Port 8081)
sudo ./target/release/udcnd -c config/node2.conf -d

# Node 3 (Tertiary - Port 8082)
sudo ./target/release/udcnd -c config/node3.conf -d
```

### 2. Optional: Run eBPF XDP Program

For packet-level processing and acceleration:

```bash
sudo ./target/release/udcn --iface ens160 --stats-interval 5
```

### 3. Verify Network

```bash
./target/release/udcn-cli daemon status
./target/release/udcn-cli network status
```

## File Transfer Operations

### Send Files

```bash
# Basic file send
./target/release/udcn-cli send \
    --file /path/to/file.txt \
    --name "/files/document" \
    --target 127.0.0.1:8081

# Advanced send with progress and custom chunk size
./target/release/udcn-cli send \
    --file /path/to/largefile.zip \
    --name "/content/archive" \
    --chunk-size 16384 \
    --progress \
    --target 127.0.0.1:8081
```

### Receive Files

```bash
# Basic file receive
./target/release/udcn-cli receive \
    --name "/files/document" \
    --output received_file.txt \
    --source 127.0.0.1:8080

# Advanced receive with progress and timeout
./target/release/udcn-cli receive \
    --name "/content/archive" \
    --output downloaded_archive.zip \
    --progress \
    --timeout 60 \
    --source 127.0.0.1:8080
```

## Network Management

### Node Management
```bash
# List all nodes
./target/release/udcn-cli node list

# Add a new node
./target/release/udcn-cli node add node4 192.168.1.100:8083

# Show node details
./target/release/udcn-cli node show node1

# Remove a node
./target/release/udcn-cli node remove node4
```

### Network Discovery
```bash
# Show network status
./target/release/udcn-cli network status

# Discover network nodes
./target/release/udcn-cli network discover
```

### Daemon Control
```bash
# Start daemon
./target/release/udcn-cli daemon start

# Stop daemon
./target/release/udcn-cli daemon stop

# Restart daemon
./target/release/udcn-cli daemon restart

# Check daemon status
./target/release/udcn-cli daemon status
```

## Performance Testing

### Network Benchmarks
```bash
# Run all benchmarks
./target/release/udcn-bench all --duration 30 --output results.json

# Specific network tests
./target/release/udcn-bench network throughput
./target/release/udcn-bench network latency
./target/release/udcn-bench network connections

# Transport layer tests
./target/release/udcn-bench transport tcp
./target/release/udcn-bench transport udp
./target/release/udcn-bench transport unix
```

### Topology Simulation
```bash
# Linear topology with 10 nodes
./target/release/udcn-bench topology \
    --topology linear \
    --nodes 10 \
    --pattern ndn_interest_data

# Mesh topology with 8 nodes
./target/release/udcn-bench topology \
    --topology mesh \
    --nodes 8 \
    --pattern high_throughput

# Tree topology with custom branching
./target/release/udcn-bench topology \
    --topology tree \
    --nodes 15 \
    --branching 3 \
    --pattern ndn_interest_data
```

## Configuration

### Default Network Configuration

The system uses these default network addresses:
- **Node 1:** 127.0.0.1:8080 (configurable in `config/node1.conf`)
- **Node 2:** 127.0.0.1:8081 (configurable in `config/node2.conf`)
- **Node 3:** 127.0.0.1:8082 (configurable in `config/node3.conf`)

### Configuration Files

- `config/node1.conf` - Primary node configuration
- `config/node2.conf` - Secondary node configuration  
- `config/node3.conf` - Tertiary node configuration
- `config/bench.conf` - Benchmark configuration

### Key Settings

Each node configuration includes:
- **Network interface:** `ens160` (modify as needed)
- **Content store size:** 10,000 entries
- **Routing strategy:** Multicast with interest aggregation
- **PIT lifetime:** 5 seconds
- **Maximum connections:** 100

## Example: Complete Workflow

1. **Build the system:**
   ```bash
   ./build-all.sh
   ```

2. **Start a 3-node network:**
   ```bash
   sudo ./target/release/udcnd -c config/node1.conf &
   sudo ./target/release/udcnd -c config/node2.conf &
   sudo ./target/release/udcnd -c config/node3.conf &
   ```

3. **Verify network is running:**
   ```bash
   ./target/release/udcn-cli network status
   ```

4. **Send a file:**
   ```bash
   echo "Hello UDCN World!" > test.txt
   ./target/release/udcn-cli send \
       --file test.txt \
       --name "/shared/greeting" \
       --target 127.0.0.1:8080 \
       --progress
   ```

5. **Receive the file from another node:**
   ```bash
   ./target/release/udcn-cli receive \
       --name "/shared/greeting" \
       --output received_greeting.txt \
       --source 127.0.0.1:8081 \
       --progress
   ```

6. **Run performance tests:**
   ```bash
   ./target/release/udcn-bench all --output benchmark_results.json
   ```

## Features

- **Named Data Networking:** Content-centric addressing with automatic caching
- **eBPF Acceleration:** High-performance packet processing with XDP
- **Multi-transport:** Support for UDP, TCP, and Unix sockets
- **Content Caching:** Built-in content store with configurable size limits
- **Interest Aggregation:** Efficient handling of duplicate requests
- **Network Discovery:** Automatic peer discovery and health monitoring
- **File Chunking:** Efficient large file transfer with integrity checking
- **Performance Monitoring:** Comprehensive benchmarking and statistics

## Cross-compiling on macOS

```shell
CC=${ARCH}-linux-musl-gcc cargo build --package udcn --release \
  --target=${ARCH}-unknown-linux-musl \
  --config=target.${ARCH}-unknown-linux-musl.linker=\"${ARCH}-linux-musl-gcc\"
```

The cross-compiled program `target/${ARCH}-unknown-linux-musl/release/udcn` can be copied to a Linux server or VM and run there.

## License

With the exception of eBPF code, udcn is distributed under the terms
of either the [MIT license] or the [Apache License] (version 2.0), at your
option.

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in this crate by you, as defined in the Apache-2.0 license, shall
be dual licensed as above, without any additional terms or conditions.

### eBPF

All eBPF code is distributed under either the terms of the
[GNU General Public License, Version 2] or the [MIT license], at your
option.

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in this project by you, as defined in the GPL-2 license, shall be
dual licensed as above, without any additional terms or conditions.

[Apache license]: LICENSE-APACHE
[MIT license]: LICENSE-MIT
[GNU General Public License, Version 2]: LICENSE-GPL2
