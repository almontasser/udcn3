#!/bin/bash
# Build script for UDCN project
# Builds all workspace packages including eBPF

set -e

echo "Building eBPF package..."
cargo build-ebpf

echo "Building UDCN workspace (excluding eBPF)..."
cargo build --workspace --exclude udcn-ebpf

echo "All packages built successfully!"

echo ""
echo "Available binaries:"
echo "  ./target/debug/udcn          - Main UDCN binary"
echo "  ./target/debug/udcn-cli      - UDCN CLI tool"
echo "  ./target/debug/udcnd         - UDCN daemon"
echo "  ./target/debug/udcn-bench    - UDCN benchmarking tool"
echo "  ./target/bpfel-unknown-none/debug/udcn - eBPF program"
