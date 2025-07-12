# Code Style and Conventions

## Rust Toolchain
- **Channel**: nightly (specified in `rust-toolchain.toml`)
- **Components**: rust-src, rustfmt, clippy
- **Edition**: 2021
- **Minimum Rust Version**: 1.90

## Code Formatting
Configured in `rustfmt.toml`:
- **Import grouping**: StdExternalCrate
- **Import granularity**: Crate
- **Reorder imports**: true
- **Unstable features**: enabled

## Workspace Configuration
- Uses Cargo workspace with unified dependency management
- All packages share common metadata (license, authors, repository)
- Special build profiles for eBPF packages (requires debug info)

## Build Profiles
- **Development**: debug=true, opt-level=0, panic=abort
- **Release**: opt-level=3, LTO=true, strip=true, panic=abort
- **eBPF Special**: Always includes debug info even in release builds

## Naming Conventions
- Package names: kebab-case (e.g., `udcn-transport`, `udcn-cli`)
- Module names: snake_case
- Struct/Enum names: PascalCase
- Function/variable names: snake_case
- Constants: SCREAMING_SNAKE_CASE

## Code Organization
- Each major component is a separate workspace package
- Clear separation between core protocol, transport layer, and applications
- Extensive use of traits for abstraction (Transport, Service, etc.)
- Error handling with custom error types and Result patterns

## Documentation
- All public APIs should have documentation comments
- Examples in documentation where appropriate
- README files for major packages