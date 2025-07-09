# UDCN Code Style and Conventions

## Formatting Configuration
- **rustfmt.toml** with specific rules:
  - `group_imports = "StdExternalCrate"`
  - `imports_granularity = "Crate"`
  - `reorder_imports = true`
  - `unstable_features = true`

## Code Organization
- **Workspace structure**: Multiple crates with clear separation of concerns
- **Module organization**: Public re-exports in lib.rs files
- **Error handling**: Consistent use of `anyhow::Result` and `thiserror` for custom errors
- **Async patterns**: Tokio-based async/await throughout transport layers

## Naming Conventions
- **Structs**: PascalCase (e.g., `NdnQuicTransport`, `FileChunker`)
- **Functions**: snake_case (e.g., `process_interest_packet`, `extract_name_hash`)
- **Constants**: SCREAMING_SNAKE_CASE (e.g., `MAX_NAME_LENGTH`, `NDN_TLV_INTEREST`)
- **Modules**: snake_case matching filenames

## Type System Usage
- **Enums** for state representation (e.g., `PacketType`, `TransferState`)
- **Structs** with `Default` implementations where appropriate
- **Trait implementations** for common behaviors (`Display`, `Debug`, `Clone`)
- **Generics** used sparingly and meaningfully

## Documentation
- **Inline comments** for complex logic, especially in eBPF code
- **Module-level docs** explaining purpose and usage
- **Public API documentation** for exported functions and types