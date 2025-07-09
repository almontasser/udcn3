# Simple Dockerfile for UDCN testing
# Uses pre-built binaries copied into container

FROM ubuntu:24.04

# Install minimal runtime dependencies including eBPF support
RUN apt-get update && apt-get install -y \
    ca-certificates \
    iproute2 \
    libbpf1 \
    linux-headers-generic \
    kmod \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN groupadd -r udcn && useradd -r -g udcn udcn

# Create necessary directories
RUN mkdir -p /opt/udcn/bin /opt/udcn/config /opt/udcn/ebpf /var/lib/udcn /var/log/udcn \
    && chown -R udcn:udcn /opt/udcn /var/lib/udcn /var/log/udcn

# Copy pre-built binaries
# These should be built on the host with: ./build-all.sh
COPY target/debug/udcn /opt/udcn/bin/
COPY target/debug/udcnd /opt/udcn/bin/
COPY target/debug/udcn-cli /opt/udcn/bin/
COPY target/debug/udcn-bench /opt/udcn/bin/

# Copy eBPF program (compiled for host kernel)
COPY target/bpfel-unknown-none/debug/udcn /opt/udcn/ebpf/udcn

# Make binaries executable
RUN chmod +x /opt/udcn/bin/*

# Add binaries to PATH
ENV PATH="/opt/udcn/bin:$PATH"

# Set working directory
WORKDIR /opt/udcn

# Switch to non-root user
USER udcn

# Default command
CMD ["udcnd"]

# Expose common networking ports
EXPOSE 8080 8443 9090

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD udcn-cli status || exit 1

# Labels
LABEL org.opencontainers.image.title="UDCN-Test"
LABEL org.opencontainers.image.description="UDCN Test Container"
LABEL org.opencontainers.image.source="https://github.com/udcn/udcn"
LABEL org.opencontainers.image.licenses="MIT OR Apache-2.0"
