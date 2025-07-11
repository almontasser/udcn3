#!/bin/bash
# Multi-node UDCN setup script
# Creates virtual interfaces and launches nodes on separate interfaces

# Note: Removed 'set -e' to allow proper error handling in stop functions

# Configuration
NODES=3
BASE_IP="10.0.100"
INTERFACE_PREFIX="udcn"
CONFIG_DIR="config"
BIN_DIR="target/debug"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        print_error "This script must be run as root (for interface creation and eBPF)"
        echo "Usage: sudo $0 [start|stop|status|cleanup]"
        exit 1
    fi
}

# Create virtual network interfaces
create_interfaces() {
    print_status "Creating virtual network interfaces..."
    
    # Create a bridge for inter-node communication
    if ! ip link show udcn-br &>/dev/null; then
        print_status "Creating bridge udcn-br"
        ip link add name udcn-br type bridge
        ip addr add 10.0.100.254/24 dev udcn-br
        ip link set udcn-br up
    fi
    
    for i in $(seq 1 $NODES); do
        local iface="${INTERFACE_PREFIX}${i}"
        local peer_iface="${INTERFACE_PREFIX}${i}-peer"
        local ip="${BASE_IP}.${i}/24"
        
        # Check if interface already exists
        if ip link show "$iface" &>/dev/null; then
            print_warning "Interface $iface already exists, skipping creation"
        else
            print_status "Creating veth pair $iface <-> $peer_iface with IP $ip"
            
            # Create veth pair
            ip link add "$iface" type veth peer name "$peer_iface"
            
            # Configure the main interface
            ip addr add "$ip" dev "$iface"
            ip link set "$iface" up
            
            # Connect peer to bridge
            ip link set "$peer_iface" master udcn-br
            ip link set "$peer_iface" up
            
            print_success "Created veth pair $iface ($ip) <-> $peer_iface (bridged)"
        fi
    done
}

# Remove virtual network interfaces
cleanup_interfaces() {
    print_status "Cleaning up virtual network interfaces..."
    
    # First detach XDP programs from all interfaces
    for i in $(seq 1 $NODES); do
        local iface="${INTERFACE_PREFIX}${i}"
        if ip link show "$iface" &>/dev/null; then
            print_status "Detaching XDP programs from $iface"
            ip link set "$iface" xdpgeneric off 2>/dev/null || true
            ip link set "$iface" xdp off 2>/dev/null || true
        fi
    done
    
    # Wait a moment for XDP programs to fully detach
    sleep 2
    
    # Remove veth pairs
    for i in $(seq 1 $NODES); do
        local iface="${INTERFACE_PREFIX}${i}"
        local peer_iface="${INTERFACE_PREFIX}${i}-peer"
        
        if ip link show "$iface" &>/dev/null; then
            print_status "Removing veth pair $iface"
            # First try to bring the interface down
            ip link set "$iface" down 2>/dev/null || true
            # Then delete it
            ip link delete "$iface" 2>/dev/null || true
            print_success "Removed veth pair $iface"
        else
            print_warning "Interface $iface not found, skipping"
        fi
        
        # Also check for orphaned peer interfaces
        if ip link show "$peer_iface" &>/dev/null; then
            print_status "Removing orphaned peer interface $peer_iface"
            ip link delete "$peer_iface" 2>/dev/null || true
        fi
    done
    
    # Remove bridge
    if ip link show udcn-br &>/dev/null; then
        print_status "Removing bridge udcn-br"
        ip link set udcn-br down 2>/dev/null || true
        ip link delete udcn-br 2>/dev/null || true
        print_success "Removed bridge udcn-br"
    fi
    
    # Clean up any remaining UDCN interfaces that might exist
    for iface in $(ip link show | grep -o "udcn[0-9]*" | sort -u 2>/dev/null || true); do
        if ip link show "$iface" &>/dev/null; then
            print_warning "Cleaning up remaining interface $iface"
            ip link delete "$iface" 2>/dev/null || true
        fi
    done
}

# Update configuration files with new interfaces
update_configs() {
    print_status "Updating configuration files..."
    
    for i in $(seq 1 $NODES); do
        local config_file="${CONFIG_DIR}/node${i}.conf"
        local iface="${INTERFACE_PREFIX}${i}"
        local ip="${BASE_IP}.${i}"
        local port=$((8079 + i))
        
        if [[ -f "$config_file" ]]; then
            print_status "Updating $config_file for interface $iface"
            
            # Create backup
            cp "$config_file" "${config_file}.backup"
            
            # Update interface and bind address
            sed -i "s/interface = .*/interface = \"$iface\"/" "$config_file"
            sed -i "s/bind_address = .*/bind_address = \"$ip\"/" "$config_file"
            sed -i "s/port = .*/port = $port/" "$config_file"
            
            # Update FIB entries to point to other nodes with new IP addresses
            for j in $(seq 1 $NODES); do
                if [[ $i -ne $j ]]; then
                    local other_ip="${BASE_IP}.${j}"
                    local other_port=$((8079 + j))
                    
                    # Update existing FIB entries with new IP addresses
                    sed -i "s/172\.20\.0\.1[0-9]:808[0-9]/${other_ip}:${other_port}/g" "$config_file"
                fi
            done
            
            # Add a general routing entry for file transfers
            if ! grep -q "prefix = \"/\"" "$config_file"; then
                # Add a catch-all route to other nodes
                for j in $(seq 1 $NODES); do
                    if [[ $i -ne $j ]]; then
                        local other_ip="${BASE_IP}.${j}"
                        local other_port=$((8079 + j))
                        cat >> "$config_file" << EOF

[[routing.fib_entries]]
prefix = "/"
next_hop = "${other_ip}:${other_port}"
cost = 1
enabled = true
EOF
                    fi
                done
            fi
            
            print_success "Updated $config_file"
        else
            print_error "Configuration file $config_file not found"
        fi
    done
}

# Restore original configuration files
restore_configs() {
    print_status "Restoring original configuration files..."
    
    for i in $(seq 1 $NODES); do
        local config_file="${CONFIG_DIR}/node${i}.conf"
        local backup_file="${config_file}.backup"
        
        if [[ -f "$backup_file" ]]; then
            mv "$backup_file" "$config_file"
            print_success "Restored $config_file"
        fi
    done
}

# Start UDCN nodes
start_nodes() {
    print_status "Starting UDCN nodes..."
    
    # Check if binaries exist
    if [[ ! -f "${BIN_DIR}/udcnd" ]]; then
        print_error "UDCN daemon binary not found at ${BIN_DIR}/udcnd"
        print_error "Please build the project first: ./build-all.sh"
        exit 1
    fi
    
    # Clean up any existing XDP programs first
    print_status "Cleaning up existing XDP programs..."
    for i in $(seq 1 $NODES); do
        local iface="${INTERFACE_PREFIX}${i}"
        if ip link show "$iface" &>/dev/null; then
            # Try to remove XDP program if attached
            ip link set "$iface" xdpgeneric off 2>/dev/null || true
        fi
    done
    
    for i in $(seq 1 $NODES); do
        local config_file="${CONFIG_DIR}/node${i}.conf"
        local pid_file="/tmp/udcnd-node${i}.pid"
        local log_file="/tmp/udcnd-node${i}.log"
        
        if [[ -f "$config_file" ]]; then
            print_status "Starting node $i with config $config_file"
            
            # Start daemon in background
            RUST_LOG=info "${BIN_DIR}/udcnd" -c "$config_file" -d > "$log_file" 2>&1 &
            local pid=$!
            echo $pid > "$pid_file"
            
            # Wait a moment and check if process is still running
            sleep 3
            if kill -0 $pid 2>/dev/null; then
                print_success "Node $i started (PID: $pid, Log: $log_file)"
            else
                print_error "Node $i failed to start. Check log: $log_file"
                tail -n 10 "$log_file"
            fi
        else
            print_error "Configuration file $config_file not found"
        fi
    done
}

# Stop UDCN nodes
stop_nodes() {
    print_status "Stopping UDCN nodes..."
    
    # First, try to stop nodes using PID files
    for i in $(seq 1 $NODES); do
        local pid_file="/tmp/udcnd-node${i}.pid"
        
        if [[ -f "$pid_file" ]]; then
            local pid=$(cat "$pid_file")
            if kill -0 $pid 2>/dev/null; then
                print_status "Stopping node $i (PID: $pid)"
                kill $pid
                
                # Wait for process to stop
                local count=0
                while kill -0 $pid 2>/dev/null && [[ $count -lt 10 ]]; do
                    sleep 1
                    ((count++))
                done
                
                if kill -0 $pid 2>/dev/null; then
                    print_warning "Node $i did not stop gracefully, force killing"
                    kill -9 $pid
                fi
                
                print_success "Node $i stopped"
            else
                print_warning "Node $i was not running"
            fi
            rm -f "$pid_file"
        else
            print_warning "PID file for node $i not found"
        fi
    done
    
    # Force kill any remaining udcnd processes
    print_status "Ensuring all UDCN processes are stopped..."
    local remaining_pids=$(pgrep -f "udcnd.*-c.*config/node[0-9]*.conf" 2>/dev/null || true)
    if [[ -n "$remaining_pids" ]]; then
        print_warning "Found remaining UDCN processes, force killing..."
        echo "$remaining_pids" | xargs -r kill -9 2>/dev/null || true
        sleep 2
    fi
    
    # Clean up XDP programs that might be attached
    print_status "Cleaning up XDP programs..."
    for i in $(seq 1 $NODES); do
        local iface="${INTERFACE_PREFIX}${i}"
        if ip link show "$iface" &>/dev/null; then
            # Try to remove XDP program if attached
            ip link set "$iface" xdpgeneric off 2>/dev/null || true
            ip link set "$iface" xdp off 2>/dev/null || true
        fi
    done
    
    # Clean up any remaining PID files
    rm -f /tmp/udcnd-node*.pid 2>/dev/null || true
}

# Show status of nodes
show_status() {
    print_status "UDCN Multi-node Status:"
    echo
    
    # Check interfaces
    echo "Network Interfaces:"
    for i in $(seq 1 $NODES); do
        local iface="${INTERFACE_PREFIX}${i}"
        if ip link show "$iface" &>/dev/null; then
            local ip=$(ip addr show "$iface" | grep 'inet ' | awk '{print $2}')
            echo "  ✓ $iface: $ip"
        else
            echo "  ✗ $iface: not found"
        fi
    done
    
    echo
    echo "UDCN Nodes:"
    for i in $(seq 1 $NODES); do
        local pid_file="/tmp/udcnd-node${i}.pid"
        local log_file="/tmp/udcnd-node${i}.log"
        
        if [[ -f "$pid_file" ]]; then
            local pid=$(cat "$pid_file")
            if kill -0 $pid 2>/dev/null; then
                echo "  ✓ Node $i: Running (PID: $pid)"
            else
                echo "  ✗ Node $i: Dead (PID file exists but process not running)"
            fi
        else
            echo "  ✗ Node $i: Not running"
        fi
        
        if [[ -f "$log_file" ]]; then
            echo "    Log: $log_file"
        fi
    done
    
    echo
    echo "To test file transfer between nodes:"
    echo "  # Send file from external client to node 1:"
    echo "  ./target/debug/udcn-cli send --file test.txt --name \"/test/file\" --target ${BASE_IP}.1:8080"
    echo
    echo "  # Receive file from node 2:"
    echo "  ./target/debug/udcn-cli receive --name \"/test/file\" --output received.txt --source ${BASE_IP}.2:8081"
}

# Main script logic
main() {
    local action="${1:-start}"
    
    case "$action" in
        "start")
            check_root
            create_interfaces
            update_configs
            start_nodes
            echo
            print_success "Multi-node UDCN setup complete!"
            show_status
            ;;
        "stop")
            check_root
            stop_nodes
            restore_configs
            print_success "All nodes stopped and configs restored"
            ;;
        "status")
            show_status
            ;;
        "cleanup")
            check_root
            stop_nodes
            cleanup_interfaces
            restore_configs
            print_success "Complete cleanup finished"
            ;;
        "restart")
            check_root
            stop_nodes
            start_nodes
            show_status
            ;;
        *)
            echo "Usage: $0 [start|stop|status|cleanup|restart]"
            echo
            echo "Commands:"
            echo "  start   - Create interfaces, update configs, and start nodes"
            echo "  stop    - Stop all nodes and restore original configs"
            echo "  status  - Show status of interfaces and nodes"
            echo "  cleanup - Stop nodes, remove interfaces, and restore configs"
            echo "  restart - Stop and start nodes"
            echo
            echo "This script creates virtual interfaces udcn1, udcn2, udcn3 with IPs"
            echo "10.0.100.1/24, 10.0.100.2/24, 10.0.100.3/24 respectively."
            exit 1
            ;;
    esac
}

# Run main function with all arguments
main "$@"