# Changelog

## 0.2.0 (2023-02-02)

### Added
- `Debug`, `Clone`, `Copy` derives for `Tag`. 
- `generate_confirmation_key` returns both the key and the timestamp.

## 0.3.0 (2023-06-26)

### Changed
- Bump `base64` to `0.21.2`.
- String paramters are now generic `AsRef<[u8]>`.