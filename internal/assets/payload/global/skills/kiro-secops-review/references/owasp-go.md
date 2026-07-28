# Review reference — Go

BAD/GOOD patterns for the Go ecosystem.

## Injection (A05)
```go
// BAD: concatenated SQL
db.Query(fmt.Sprintf("SELECT * FROM users WHERE id = %s", id))
// GOOD: parameterized
db.Query("SELECT * FROM users WHERE id = $1", id)
```
```go
// BAD: command via shell
exec.Command("sh", "-c", "ping "+userInput).Run()
// GOOD: separate args, no shell
exec.Command("ping", userInput).Run()
```

## Secrets (A04/A02)
```go
// BAD
apiKey := "sk-proj-xxxxx"
// GOOD
apiKey := os.Getenv("API_KEY")
```

## SSRF (A01)
- Validate the URL host against an allowlist before `http.Get`/`http.Client.Do`.

## Cryptography (A04)
- Randomness: `crypto/rand` (never `math/rand`) for tokens/secrets.
- Passwords: `golang.org/x/crypto/bcrypt` or argon2 — never `md5`/`sha1`.

## Deserialization / parse (A08)
- Be careful when `Unmarshal`-ing into `interface{}` from untrusted data; validate the schema.

## Dependencies / SCA (A03)
```bash
govulncheck ./...
go list -m -u all      # outdated dependencies
```

## Tools
`govulncheck`, `gosec ./...`, `semgrep --config p/golang`, `trivy fs .`, `gitleaks detect`.
