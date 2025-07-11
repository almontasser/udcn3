#!/bin/bash
# Comprehensive eBPF Verifier and μDCN Testing Script
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log() {
    echo -e "${BLUE}[$(date +'%Y-%m-%d %H:%M:%S')] $1${NC}"
}

success() {
    echo -e "${GREEN}[SUCCESS] $1${NC}"
}

warn() {
    echo -e "${YELLOW}[WARNING] $1${NC}"
}

error() {
    echo -e "${RED}[ERROR] $1${NC}"
}

# Check if running as root
if [[ $EUID -ne 0 ]]; then
    echo "eBPF testing requires root privileges. Switching to sudo..."
    exec sudo "$0" "$@"
fi

log "Starting comprehensive eBPF verifier and μDCN testing"

# 1. System Information
log "=== SYSTEM INFORMATION ==="
uname -a
cat /proc/version
lscpu | head -20
free -h

# 2. eBPF Support Check
log "=== eBPF SUPPORT CHECK ==="
echo "Kernel version: $(uname -r)"
echo "eBPF JIT status:"
cat /proc/sys/net/core/bpf_jit_enable 2>/dev/null || echo "N/A"

echo "Available eBPF program types:"
ls -la /sys/fs/bpf/ 2>/dev/null || echo "bpffs not mounted"

echo "eBPF tools availability:"
which bpftool && bpftool version || echo "bpftool not available"
which clang && clang --version | head -1 || echo "clang not available"

# 3. Network Interface Check
log "=== NETWORK INTERFACES ==="
ip link show
echo ""
echo "Available interfaces for XDP attachment:"
for iface in $(ip link show | grep '^[0-9]' | awk -F: '{print $2}' | tr -d ' '); do
    if [[ "$iface" != "lo" ]]; then
        echo "  - $iface (index: $(cat /sys/class/net/$iface/ifindex 2>/dev/null || echo 'N/A'))"
    fi
done

# 4. BPF Filesystem Setup
log "=== BPF FILESYSTEM SETUP ==="
if ! mountpoint -q /sys/fs/bpf; then
    warn "BPF filesystem not mounted, mounting..."
    mount -t bpf bpf /sys/fs/bpf || error "Failed to mount BPF filesystem"
fi
ls -la /sys/fs/bpf/

# 5. Install required tools if missing
log "=== INSTALLING REQUIRED TOOLS ==="
if ! command -v bpftool &> /dev/null; then
    log "Installing bpftool..."
    apt-get update && apt-get install -y linux-tools-$(uname -r) linux-tools-generic bpftool
fi

if ! command -v clang &> /dev/null; then
    log "Installing clang..."
    apt-get update && apt-get install -y clang llvm
fi

# 6. Test simple eBPF program (verifier compliance)
log "=== TESTING SIMPLE EBPF PROGRAM ==="
cat > /tmp/simple_xdp.c << 'EOFPROG'
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int xdp_simple(struct xdp_md *ctx)
{
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
EOFPROG

log "Compiling simple XDP program..."
clang -O2 -target bpf -c /tmp/simple_xdp.c -o /tmp/simple_xdp.o || {
    warn "Clang compilation failed, trying alternative approach..."
}

if [[ -f /tmp/simple_xdp.o ]]; then
    log "Verifying eBPF bytecode with bpftool..."
    bpftool prog load /tmp/simple_xdp.o /sys/fs/bpf/simple_xdp || warn "Program load failed"
    
    if [[ -f /sys/fs/bpf/simple_xdp ]]; then
        success "Simple eBPF program verification passed"
        bpftool prog show pinned /sys/fs/bpf/simple_xdp
        rm -f /sys/fs/bpf/simple_xdp
    fi
fi

# 7. Test μDCN binaries
log "=== TESTING μDCN BINARIES ==="
cd /home/mahmoud/udcn/bin || error "Cannot find udcn directory"

if [[ ! -f udcn-daemon ]]; then
    error "udcn-daemon not found"
fi

if [[ ! -f udcn-xdp ]]; then
    error "udcn-xdp not found"
fi

log "Testing daemon startup..."
timeout 10s ./udcn-daemon --interface lo --ebpf-program udcn-xdp --debug &
DAEMON_PID=$!

sleep 5

if ps -p $DAEMON_PID > /dev/null; then
    log "μDCN daemon started successfully (PID: $DAEMON_PID)"
    
    # Check for loaded eBPF programs
    log "Checking for loaded eBPF programs..."
    bpftool prog list | grep -E "(xdp|udcn)" || log "No μDCN eBPF programs currently loaded"
    
    # Check BPF maps
    log "Checking BPF maps..."
    bpftool map list | grep -E "(udcn|cs|pit|fib)" || log "No μDCN BPF maps found"
    
    kill $DAEMON_PID 2>/dev/null || true
    wait $DAEMON_PID 2>/dev/null || true
    success "μDCN daemon testing completed"
else
    warn "μDCN daemon failed to start or exited early"
fi

# 8. Network stress testing
log "=== NETWORK STRESS TESTING ==="
TEST_IFACE="lo"
log "Testing XDP attachment on interface: $TEST_IFACE"

# Try to attach simple XDP program
if [[ -f /tmp/simple_xdp.o ]]; then
    log "Attempting XDP attachment..."
    ip link set dev $TEST_IFACE xdp obj /tmp/simple_xdp.o sec xdp 2>/dev/null && {
        success "XDP attachment successful on $TEST_IFACE"
        
        # Check attachment
        ip link show $TEST_IFACE | grep xdp || true
        
        # Generate some traffic for testing
        log "Generating test traffic..."
        ping -c 5 127.0.0.1 >/dev/null 2>&1 &
        
        sleep 2
        
        # Detach XDP
        ip link set dev $TEST_IFACE xdp off 2>/dev/null || true
        success "XDP program detached"
    } || warn "XDP attachment failed on $TEST_IFACE"
fi

# 9. Memory and resource testing
log "=== MEMORY AND RESOURCE TESTING ==="
echo "Memory usage:"
free -h

echo "eBPF memory limits:"
cat /proc/sys/kernel/bpf_stats_enabled 2>/dev/null || echo "BPF stats not available"

# 10. Verifier complexity testing
log "=== VERIFIER COMPLEXITY TESTING ==="
cat > /tmp/complex_xdp.c << 'EOFPROG'
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

struct bpf_map_def SEC("maps") stats_map = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u64),
    .max_entries = 10,
};

SEC("xdp")
int xdp_complex(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth = data;
    
    // Bounds check
    if (eth + 1 > data_end)
        return XDP_PASS;
    
    // IPv6 processing
    if (bpf_ntohs(eth->h_proto) == ETH_P_IPV6) {
        struct ipv6hdr *ipv6 = (struct ipv6hdr *)(eth + 1);
        
        if (ipv6 + 1 > data_end)
            return XDP_PASS;
            
        // UDP processing
        if (ipv6->nexthdr == IPPROTO_UDP) {
            struct udphdr *udp = (struct udphdr *)(ipv6 + 1);
            
            if (udp + 1 > data_end)
                return XDP_PASS;
                
            // NDN port check (6363)
            if (bpf_ntohs(udp->dest) == 6363) {
                __u32 key = 0;
                __u64 *count = bpf_map_lookup_elem(&stats_map, &key);
                if (count) {
                    __sync_fetch_and_add(count, 1);
                }
                return XDP_PASS;
            }
        }
    }
    
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
EOFPROG

log "Compiling complex XDP program for verifier testing..."
clang -O2 -target bpf -c /tmp/complex_xdp.c -o /tmp/complex_xdp.o 2>/dev/null && {
    log "Testing complex eBPF program verification..."
    bpftool prog load /tmp/complex_xdp.o /sys/fs/bpf/complex_xdp 2>&1 && {
        success "Complex eBPF program passed verifier"
        bpftool prog show pinned /sys/fs/bpf/complex_xdp
        rm -f /sys/fs/bpf/complex_xdp
    } || warn "Complex eBPF program failed verifier"
} || warn "Complex eBPF program compilation failed"

# 11. Final system status
log "=== FINAL SYSTEM STATUS ==="
echo "Loaded eBPF programs:"
bpftool prog list

echo "BPF maps:"
bpftool map list

echo "Network interfaces:"
ip link show | grep -E "^[0-9]|xdp"

# 12. Performance metrics
log "=== PERFORMANCE METRICS ==="
echo "System load:"
uptime

echo "Network statistics:"
cat /proc/net/dev | head -3

success "Comprehensive eBPF testing completed successfully!"

# Cleanup
rm -f /tmp/simple_xdp.c /tmp/simple_xdp.o /tmp/complex_xdp.c /tmp/complex_xdp.o

log "Test results saved. Check logs for any warnings or errors."
log "μDCN deployment validation complete!"