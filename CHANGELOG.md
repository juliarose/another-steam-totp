# Changelog

## 0.4.2 (2025-07-24)

### Changed
- Updated `Cargo.toml` to set the minimum supported Rust version (MSRV) to `1.60.0` for better compatibility.

## 0.4.1 (2025-07-22)

### Fixed
- Documentation links.

## 0.4.0 (2025-07-18)

### Added
- Added `get_device_id_with_salt` method.
- Added `get_steam_server_time_offset_sync` method for synchronous time offset retrieval. Enable the `ureq` feature to use this method.

### Changed
- Generating codes now allows for hex-encoded strings.
- Added `Reqwest` variant to `Error` for `reqwest` feature.
- Added `Ureq` variant to `Error` for `ureq` feature.
- `generate_confirmation_key` now returns a `u64` timestamp instead of `i64`.

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
