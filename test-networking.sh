#!/bin/bash
# UDCN Networking Test Script

set -e

echo "=== UDCN Networking Configuration Test ==="
echo

# Test 1: Basic network connectivity
echo "1. Testing basic network connectivity..."
docker-compose exec udcn-node1 ping -c 3 udcn-node2 2>/dev/null && echo "✓ Node1 -> Node2 connectivity OK" || echo "✗ Node1 -> Node2 connectivity FAILED"
docker-compose exec udcn-node2 ping -c 3 udcn-node3 2>/dev/null && echo "✓ Node2 -> Node3 connectivity OK" || echo "✗ Node2 -> Node3 connectivity FAILED"
docker-compose exec udcn-node3 ping -c 3 udcn-node1 2>/dev/null && echo "✓ Node3 -> Node1 connectivity OK" || echo "✗ Node3 -> Node1 connectivity FAILED"

echo

# Test 2: DNS resolution
echo "2. Testing DNS resolution..."
docker-compose exec udcn-node1 nslookup udcn-node2 2>/dev/null && echo "✓ DNS resolution working" || echo "✗ DNS resolution FAILED"

echo

# Test 3: Port accessibility
echo "3. Testing port accessibility..."
docker-compose exec udcn-cli-test nc -zv udcn-node1 8080 2>/dev/null && echo "✓ Node1 port 8080 accessible" || echo "✗ Node1 port 8080 NOT accessible"
docker-compose exec udcn-cli-test nc -zv udcn-node2 8081 2>/dev/null && echo "✓ Node2 port 8081 accessible" || echo "✗ Node2 port 8081 NOT accessible"
docker-compose exec udcn-cli-test nc -zv udcn-node3 8082 2>/dev/null && echo "✓ Node3 port 8082 accessible" || echo "✗ Node3 port 8082 NOT accessible"

echo

# Test 4: Service discovery
echo "4. Testing service discovery..."
docker-compose exec udcn-cli-test getent hosts udcn-primary 2>/dev/null && echo "✓ Primary node alias resolved" || echo "✗ Primary node alias NOT resolved"
docker-compose exec udcn-cli-test getent hosts udcn-secondary 2>/dev/null && echo "✓ Secondary node alias resolved" || echo "✗ Secondary node alias NOT resolved"
docker-compose exec udcn-cli-test getent hosts udcn-tertiary 2>/dev/null && echo "✓ Tertiary node alias resolved" || echo "✗ Tertiary node alias NOT resolved"

echo

# Test 5: Load balancer (if enabled)
echo "5. Testing load balancer..."
curl -f http://localhost:8000/health 2>/dev/null && echo "✓ Load balancer health check OK" || echo "✗ Load balancer health check FAILED (may not be enabled)"

echo
echo "=== Networking test completed ==="