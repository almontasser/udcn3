# UDCN Testing Framework

## Test Organization
- **Unit tests**: Located in `#[cfg(test)]` modules within each source file
- **Integration tests**: Cross-module testing within workspace
- **Async tests**: Using `#[tokio::test]` for async test functions

## Test Patterns
- **Standard tests**: `#[test]` attribute for synchronous tests
- **Async tests**: `#[tokio::test]` for async functionality
- **Test modules**: Organized by feature (e.g., `hierarchy_tests`, `validation_tests`)

## Test Dependencies
- **tempfile**: For temporary file/directory creation in tests
- **std::io::Write**: For file writing in test scenarios
- **tokio::time**: For async timing in tests

## Test Coverage Areas
- **Core protocols**: NDN packet processing, TLV encoding/decoding
- **Transport layers**: QUIC, TCP, UDP connection handling
- **File operations**: Chunking, reassembly, integrity verification
- **Name processing**: Hierarchical naming, validation, normalization
- **Performance**: Benchmarking with criterion (inferred from bench profile)

## Running Tests
```bash
# All tests
cargo test-all

# Package-specific tests
cargo test --package udcn-core

# Test with features
cargo test --workspace --all-features

# Integration tests
cargo test --workspace --all-targets
```

## Test Utilities
- **Mock objects**: For transport layer testing
- **Temporary files**: For file transfer testing
- **Network simulation**: For protocol testing
- **Performance benchmarks**: Located in udcn-bench package