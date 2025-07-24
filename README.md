# another-steam-totp

Provides functionality relating to Steam TOTP. Based on <https://github.com/DoctorMcKay/node-steam-totp>. Designed to be easy-to-use while providing all necessary features.

## Usage

```rust
use another_steam_totp::generate_auth_code;

let shared_secret = "000000000000000000000000000=";
let time_offset = None;
// Generates the 5-character time-based one-time password using
// your shared_secret.
let code = generate_auth_code(shared_secret, time_offset).unwrap();

assert_eq!(code.len(), 5);
```

## Features
- Generating 5-character TOTP codes used for authentication with Steam.
- Generating confirmation keys and device IDs used for confirmations.
- Getting the current time offset from Steam's servers in seconds using the Steam Web API (enable `reqwest` feature, or `ureq` feature for a synchronous version).

## Installation
Add this to your `Cargo.toml`:

```toml
[dependencies]
another-steam-totp = "0.4"
```

Or with `reqwest` feature:

```toml
[dependencies]
another-steam-totp = { version = "0.4", features = ["reqwest"] }
```

## License

[MIT](https://github.com/juliarose/another-steam-totp/tree/main/LICENSE)