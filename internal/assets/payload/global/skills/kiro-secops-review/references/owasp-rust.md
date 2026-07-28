# Review reference — Rust

BAD/GOOD patterns for the Rust ecosystem.

## Injection (A05)
```rust
// BAD: formatted SQL
sqlx::query(&format!("SELECT * FROM users WHERE id = {}", id));
// GOOD: parameterized (sqlx/diesel)
sqlx::query!("SELECT * FROM users WHERE id = $1", id);
```
```rust
// BAD: command via shell
Command::new("sh").arg("-c").arg(format!("ping {}", host)).status();
// GOOD: separate args
Command::new("ping").arg(host).status();
```

## Secrets (A04/A02)
```rust
// BAD
let api_key = "sk-proj-xxxxx";
// GOOD
let api_key = std::env::var("API_KEY").expect("API_KEY not set");
```

## `unsafe` and memory
- Minimize and justify `unsafe` blocks; most of the code should be safe Rust.

## Cryptography (A04)
- Crypto randomness: `OsRng` (`rand::rngs::OsRng`) / `getrandom` — not `thread_rng` for secrets.
- Passwords: `argon2`/`bcrypt` crates.

## Deserialization (A08)
- `serde`: validate/limit what is deserialized from untrusted sources.

## Dependencies / SCA (A03)
```bash
cargo audit          # RustSec advisories
cargo deny check     # licenses + advisories + bans
```

## Tools
`cargo audit`, `cargo deny`, `cargo clippy`, `semgrep --config p/rust`, `trivy fs .`, `gitleaks`.
