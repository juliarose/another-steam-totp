# another-steam-totp

Provides functionality relating to Steam TOTP. Based on <https://github.com/DoctorMcKay/node-steam-totp>. Designed to be easy-to-use while providing all necessary features.

```rs
use another_steam_totp::generate_auth_code;

let identity_secret = String::from("000000000000000000000000000=");
let time_offset = None;
// Generates the 5-character time-based one-time passwrod used your shared_secret.
let code = generate_auth_code(identity_secret, time_offset).unwrap();

assert_eq!(code.len(), 5);
```

## License

MIT