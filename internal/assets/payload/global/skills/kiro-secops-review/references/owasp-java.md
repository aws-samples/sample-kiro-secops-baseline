# Review reference — Java

BAD/GOOD patterns for the Java/JVM ecosystem.

## Injection (A05)
```java
// BAD
String q = "SELECT * FROM users WHERE id = " + userId;
// GOOD: PreparedStatement
PreparedStatement ps = conn.prepareStatement("SELECT * FROM users WHERE id = ?");
ps.setString(1, userId);
```
```java
// BAD: shell
Runtime.getRuntime().exec("ping " + host);
// GOOD: ProcessBuilder with args, no shell
new ProcessBuilder("ping", host).start();
```

## Insecure deserialization (A08)
- Avoid `ObjectInputStream.readObject()` on untrusted data (history of RCE).
  Prefer data formats (JSON) with explicit binding and a type allowlist.

## XXE (A02)
- Disable external entities in the XML parser:
  `dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);`

## Secrets (A04/A02)
- Never commit secrets in `application.properties`/`.yml`; use env/secret manager.
- Turn off `DEBUG`/detailed stack traces in production.

## Cryptography (A04)
- Passwords: `BCryptPasswordEncoder`/argon2 (Spring Security); `SecureRandom` for tokens.

## Dependencies / SCA (A03)
```bash
mvn org.owasp:dependency-check-maven:check -DfailBuildOnCVSS=7
# Gradle:
gradle dependencyCheckAnalyze
```

## Tools
SpotBugs + FindSecBugs, `semgrep --config p/java`, OWASP Dependency-Check, `trivy fs .`.
