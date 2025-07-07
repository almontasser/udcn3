# Multi-stage Dockerfile for UDCN Rust Project

# Build stage
FROM rust:1.90-slim as builder

# Install required system dependencies for eBPF and networking
RUN apt-get update && apt-get install -y \
    build-essential \
    pkg-config \
    libssl-dev \
    libbpf-dev \
    llvm-dev \
    libclang-dev \
    clang \
    gcc-multilib \
    && rm -rf /var/lib/apt/lists/*

# Create app directory
WORKDIR /app

# Copy workspace configuration
COPY Cargo.toml Cargo.lock rust-toolchain.toml rustfmt.toml ./
COPY build.rs ./

# Copy all crate manifests to leverage Docker layer caching
COPY udcn/Cargo.toml udcn/
COPY udcn-common/Cargo.toml udcn-common/
COPY udcn-core/Cargo.toml udcn-core/
COPY udcn-transport/Cargo.toml udcn-transport/
COPY udcn-ebpf/Cargo.toml udcn-ebpf/
COPY udcnd/Cargo.toml udcnd/
COPY udcn-cli/Cargo.toml udcn-cli/
COPY udcn-bench/Cargo.toml udcn-bench/

# Create stub source files for dependency compilation
RUN mkdir -p udcn/src udcn-common/src udcn-core/src udcn-transport/src \
    udcn-ebpf/src udcnd/src udcn-cli/src udcn-bench/src udcn-bench/benches \
    && echo "fn main() {}" > udcn/src/main.rs \
    && echo "fn main() {}" > udcn-ebpf/src/main.rs \
    && echo "fn main() {}" > udcnd/src/main.rs \
    && echo "fn main() {}" > udcn-cli/src/main.rs \
    && echo "fn main() {}" > udcn-bench/src/main.rs \
    && echo "" > udcn-common/src/lib.rs \
    && echo "" > udcn-core/src/lib.rs \
    && echo "" > udcn-transport/src/lib.rs \
    && echo "" > udcn-ebpf/src/lib.rs \
    && echo "" > udcn-bench/benches/network_bench.rs \
    && echo "" > udcn-bench/benches/transport_bench.rs

# Copy any additional build scripts if they exist
COPY udcn-ebpf/build.rs udcn-ebpf/build.rs 2>/dev/null || true
COPY udcn/build.rs udcn/build.rs 2>/dev/null || true

# Build dependencies only (this layer will be cached)
RUN cargo build --release --workspace

# Remove stub files and copy actual source code
RUN rm -rf udcn/src udcn-common/src udcn-core/src udcn-transport/src \
    udcn-ebpf/src udcnd/src udcn-cli/src udcn-bench/src udcn-bench/benches

# Copy actual source code
COPY udcn/src udcn/src/
COPY udcn-common/src udcn-common/src/
COPY udcn-core/src udcn-core/src/
COPY udcn-transport/src udcn-transport/src/
COPY udcn-ebpf/src udcn-ebpf/src/
COPY udcnd/src udcnd/src/
COPY udcn-cli/src udcn-cli/src/
COPY udcn-bench/src udcn-bench/src/
COPY udcn-bench/benches udcn-bench/benches/

# Build the actual application
RUN cargo build --release --workspace

# Runtime stage
FROM debian:bookworm-slim

# Install runtime dependencies for eBPF and networking
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    libbpf1 \
    iproute2 \
    iptables \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN groupadd -r udcn && useradd -r -g udcn udcn

# Create necessary directories
RUN mkdir -p /opt/udcn/bin /opt/udcn/config /var/lib/udcn /var/log/udcn \
    && chown -R udcn:udcn /opt/udcn /var/lib/udcn /var/log/udcn

# Copy binaries from builder stage
COPY --from=builder /app/target/release/udcn /opt/udcn/bin/
COPY --from=builder /app/target/release/udcnd /opt/udcn/bin/
COPY --from=builder /app/target/release/udcn-cli /opt/udcn/bin/
COPY --from=builder /app/target/release/udcn-bench /opt/udcn/bin/

# Add binaries to PATH
ENV PATH="/opt/udcn/bin:$PATH"

# Set working directory
WORKDIR /opt/udcn

# Switch to non-root user
USER udcn

# Default command
CMD ["udcnd"]

# Expose common networking ports (can be overridden)
EXPOSE 8080 8443 9090

# Add health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD udcn-cli status || exit 1

# Labels for better maintainability
LABEL org.opencontainers.image.title="UDCN"
LABEL org.opencontainers.image.description="User-Defined Container Network"
LABEL org.opencontainers.image.source="https://github.com/udcn/udcn"
LABEL org.opencontainers.image.licenses="MIT OR Apache-2.0"