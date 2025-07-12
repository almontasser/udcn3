# Configuration Files

## Node Configuration Files
- `config/node1.conf` - Primary node (127.0.0.1:8080)
- `config/node2.conf` - Secondary node (127.0.0.1:8081)
- `config/node3.conf` - Tertiary node (127.0.0.1:8082)

## Key Configuration Settings
Each node configuration includes:
- **Network interface**: `ens160` (modify as needed)
- **Content store size**: 10,000 entries
- **Routing strategy**: Multicast with interest aggregation
- **PIT lifetime**: 5 seconds
- **Maximum connections**: 100
- **Transport protocol**: Configurable (UDP, TCP, QUIC, UNIX)

## Default Network Addresses
- **Node 1**: 127.0.0.1:8080
- **Node 2**: 127.0.0.1:8081
- **Node 3**: 127.0.0.1:8082

## Transport Protocol Configuration
Recent development has focused on QUIC transport with bidirectional stream support for NDN Interest/Data exchanges.

## Multi-Node Setup
Use `sudo ./setup-multi-node.sh restart` to start all configured nodes with their respective configurations.

## Important Notes
- Root privileges required for some network operations
- eBPF operations require elevated privileges
- Configuration changes may require node restart
- The `--help` argument does not work for udcn-cli (known limitation)