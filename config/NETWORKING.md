# UDCN Networking Configuration

This directory contains networking configuration files for the UDCN Docker deployment.

## Network Architecture

- **Network**: `udcn_network` (172.20.0.0/16)
- **Load Balancer**: 172.20.0.2 (port 8000)
- **Service Discovery**: 172.20.0.5 (port 8090)
- **Node 1**: 172.20.0.10 (port 8080)
- **Node 2**: 172.20.0.11 (port 8081)
- **Node 3**: 172.20.0.12 (port 8082)
- **CLI Test**: 172.20.0.20
- **Benchmark**: 172.20.0.21

## Configuration Files

### Node Configurations
- `node1.conf` - Primary UDCN daemon configuration
- `node2.conf` - Secondary UDCN daemon configuration
- `node3.conf` - Tertiary UDCN daemon configuration
- `bench.conf` - Benchmark tool configuration

### Load Balancer
- `nginx/udcn-lb.conf` - Nginx load balancer configuration

## Service Discovery

Each node is configured with:
- **DNS Aliases**: node1, node2, node3 + service-specific aliases
- **Environment Variables**: UDCN_PEERS for peer discovery
- **Static Routing**: FIB entries for /udcn/discovery and /udcn/services

## Usage

### Basic 3-node setup:
```bash
docker-compose up
```

### With load balancer:
```bash
docker-compose --profile loadbalancer up
```

### With service discovery:
```bash
docker-compose --profile discovery up
```

### With CLI testing:
```bash
docker-compose --profile testing up
```

### With benchmarking:
```bash
docker-compose --profile benchmarking up
```

### All services:
```bash
docker-compose --profile loadbalancer --profile discovery --profile testing --profile benchmarking up
```

## Testing

Run the networking test script:
```bash
./test-networking.sh
```

## Load Balancer Access

- **Load Balancer**: http://localhost:8000
- **Health Check**: http://localhost:8000/health
- **Status Page**: http://localhost:8000/status

## Ports

- **8000**: Load balancer
- **8080**: Node 1 direct access
- **8081**: Node 2 direct access
- **8082**: Node 3 direct access
- **8090**: Service discovery

## Inter-Node Communication

Nodes communicate using:
- **DNS Resolution**: Using container hostnames and aliases
- **Static Routing**: FIB entries for service discovery paths
- **Environment Variables**: UDCN_PEERS for peer awareness
- **Health Checks**: Built-in health monitoring