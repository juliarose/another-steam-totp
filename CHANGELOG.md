# Changelog

## 0.3.5 (2025-07-06)

### Changed
- Added `Reqwest` to `Error` when `reqwest` feature is enabled.
- Generating codes now allow for hex-encoded strings.

### Removed
- `RequestError` for `reqwest` feature.

## 0.3.5 (2024-12-25)

### Changed
- Added `std::error::Error` implementation for `Error`.

## 0.3.4 (2024-12-25)

### Changed
- Updated dependencies.

## 0.3.3 (2024-06-23)

### Fixed
- Documentation failing to build.

## 0.3.2 (2024-06-23)

### Removed
- `thiserror` as a dependency.

## 0.3.1 (2024-02-26)

### Removed
- `byteorder` as a dependency.

## 0.3.0 (2023-06-26)

### Changed
- Bump `base64` to `0.21.2`.
- String paramters are now generic `AsRef<[u8]>`.

## 0.2.0 (2023-02-02)

### Added
- `Debug`, `Clone`, `Copy` derives for `Tag`. 
- `generate_confirmation_key` returns both the key and the timestamp.