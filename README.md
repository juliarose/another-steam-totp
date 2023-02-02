# another-steam-totp

Provides functionality relating to Steam TOTP. Based on <https://github.com/DoctorMcKay/node-steam-totp>. Designed to be easy-to-use while providing all necessary features.

```rs
use another_steam_totp::generate_auth_code;

let shared_secret = String::from("000000000000000000000000000=");
let time_offset = None;
// Generates the 5-character time-based one-time password using your shared_secret.
let code = generate_auth_code(shared_secret, time_offset).unwrap();

assert_eq!(code.len(), 5);
```

## License

MIT