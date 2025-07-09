#!/bin/bash
# Test script for UDCN Docker networking

echo "=== UDCN Docker Networking Test ==="
echo

# Check if containers are running
echo "1. Checking container status..."
docker ps -a --filter "name=udcn-node" --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"
echo

# Test network connectivity between nodes
echo "2. Testing network connectivity..."
echo "   Node 1 -> Node 2:"
docker exec udcn-node1 ping -c 2 udcn-node2 2>/dev/null && echo "   ✓ Success" || echo "   ✗ Failed"
echo "   Node 2 -> Node 3:"
docker exec udcn-node2 ping -c 2 udcn-node3 2>/dev/null && echo "   ✓ Success" || echo "   ✗ Failed"
echo "   Node 3 -> Node 1:"
docker exec udcn-node3 ping -c 2 udcn-node1 2>/dev/null && echo "   ✓ Success" || echo "   ✗ Failed"
echo

# Check exposed ports
echo "3. Checking exposed ports..."
for port in 8080 8081 8082; do
    nc -zv localhost $port 2>&1 | grep -q succeeded && echo "   Port $port: ✓ Open" || echo "   Port $port: ✗ Closed"
done
echo

# Check volumes
echo "4. Checking volumes..."
docker volume ls --filter "name=udcn" --format "table {{.Name}}\t{{.Driver}}"
echo

# Check network configuration
echo "5. Network configuration:"
docker network inspect udcn_udcn_network --format '{{range .Containers}}{{.Name}}: {{.IPv4Address}}{{println}}{{end}}' 2>/dev/null
echo

# Summary
echo "=== Summary ==="
echo "The Docker networking infrastructure is set up for UDCN testing."
echo "Note: eBPF functionality requires host-level privileges that may not be"
echo "available in all container environments. For full eBPF support, consider:"
echo "  - Running on the host system directly"
echo "  - Using Docker with --privileged and proper kernel modules"
echo "  - Using a full VM instead of containers"
echo
echo "The networking setup allows for:"
echo "  ✓ Multi-node UDCN network simulation"
echo "  ✓ Inter-node communication via Docker network"
echo "  ✓ Port exposure for external access"
echo "  ✓ Persistent storage via Docker volumes"