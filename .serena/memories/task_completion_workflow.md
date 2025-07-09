# UDCN Task Completion Workflow

## Before Code Changes
1. **Run checks**: `cargo check-all` to ensure current code compiles
2. **Review tests**: Check if existing tests cover the area you're modifying

## During Development
1. **Incremental builds**: Use `cargo check` for fast feedback
2. **Module-specific testing**: `cargo test --package <package-name>` for targeted testing
3. **Format code**: `cargo fmt-all` before committing

## After Implementation
1. **Format code**: `cargo fmt-all` (required)
2. **Run linter**: `cargo clippy-all` (fix warnings)
3. **Run tests**: `cargo test-all` (all tests must pass)
4. **Build check**: `cargo build --workspace` (ensure compilation)

## For eBPF Changes
1. **Build eBPF**: `cargo build-ebpf` (check eBPF compilation)
2. **Integration test**: Test with actual network interface (requires root)
3. **Performance check**: Run relevant benchmarks if performance-critical

## Special Considerations
- **Root permissions**: Main udcn binary requires root for eBPF loading
- **Network interface**: Default is eth0, specify with `--iface` if different
- **eBPF debugging**: Use `RUST_LOG=debug` for verbose eBPF logging
- **Cross-compilation**: Test on target architecture if cross-compiling

## Git Workflow
- **Feature branches**: Create branches for new features
- **Commit messages**: Use conventional commits format
- **Pre-commit**: Ensure all checks pass before pushing