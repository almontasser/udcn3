#!/bin/bash
# Docker entrypoint script for UDCN daemon

echo "Starting UDCN daemon..."
echo "Checking eBPF support..."

# Check if we can create BPF maps
if ! command -v bpftool &> /dev/null; then
    echo "WARNING: bpftool not available, eBPF functionality may be limited"
fi

# Try to load a simple eBPF program to test support
if [ -f /sys/fs/bpf ]; then
    echo "BPF filesystem is mounted"
else
    echo "WARNING: BPF filesystem not available"
fi

# Check kernel version
echo "Kernel version: $(uname -r)"

# For testing purposes, we'll run the daemon even if eBPF fails
# In a production environment, you'd want proper eBPF support
echo "NOTE: Running in Docker container - eBPF support may be limited"
echo "For full eBPF support, run on the host or use a VM"

# Start the daemon
exec "$@"