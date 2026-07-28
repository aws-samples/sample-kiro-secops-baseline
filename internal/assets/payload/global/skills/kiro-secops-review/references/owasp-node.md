# Review reference — TypeScript / Node.js

BAD→GOOD patterns, tool rules, and regex. Based on: OWASP Node.js Cheat Sheet, CWE,
eslint-plugin-security, typescript-eslint, Semgrep.

## Vulnerabilities (BAD → GOOD)

### Command injection — CWE-78 / A05
```ts
// BAD: exec() runs via /bin/sh
exec(`ping ${host}`);
// GOOD
execFile('ping', ['-c', '1', String(host)]);   // no shell; + host allowlist
```

### eval / Function / vm — CWE-94
```ts
// BAD
eval(x); new Function('a', code); setTimeout(codeStr, 100);   // string => eval
// GOOD
JSON.parse(x);                                                // data, not code
```

### Prototype pollution — CWE-1321 / A05
```ts
// BAD: recursive merge of user JSON  →  {"__proto__":{"isAdmin":true}}
// GOOD
const BAD = new Set(['__proto__', 'constructor', 'prototype']);
for (const k of Object.keys(src)) if (BAD.has(k)) throw new Error('forbidden key');
// Object.create(null) / Map / structuredClone; lodash >= 4.17.21; node --disable-proto=delete
```

### ReDoS — CWE-1333 / A02
```ts
// BAD
/^(a+)+$/.test(input); new RegExp(userInput);
// GOOD: limit size; avoid (x+)+ and overlapping alternation; RE2 for regex from an untrusted source
```

### XSS — CWE-79 / A05
```ts
// BAD
el.innerHTML = x; document.write(x); <div dangerouslySetInnerHTML={{ __html: x }} />
// GOOD
el.textContent = x; DOMPurify.sanitize(x)
```

### SSRF / path traversal — CWE-918 / CWE-22 / A01
```ts
// BAD
fetch(req.query.url); fs.readFile(path.join('/data', req.query.f));
// GOOD: allowlist host+scheme, block private/link-local IP; resolve and check base prefix
```

### Deserialization / JWT — CWE-502 / CWE-347 / A08/A07
```ts
// BAD
require('node-serialize').unserialize(x); jwt.verify(t, key); jwt.decode(t)
// GOOD
JSON.parse(x); jwt.verify(t, key, { algorithms: ['RS256'], issuer, audience })
```

### SQLi / NoSQLi — CWE-89 / CWE-943 / A05
```ts
// BAD
db.query(`... id=${id}`); User.find({ pass: req.body.pass });   // {"pass":{"$gt":""}}
// GOOD
db.query('... id=$1', [id]);   // validate string type (zod); express-mongo-sanitize; forbid $where
```

### Crypto / secrets — CWE-327/338/798 / A04
```ts
// BAD
crypto.createHash('md5'); Math.random(); const K = 'sk_live_...';
// GOOD
argon2.hash(pw); crypto.randomBytes(32); process.env.API_KEY
```
Never put a secret in `NEXT_PUBLIC_*` / `VITE_*` (inlined into the client bundle).

### Missing controls — CORS `*` (CWE-942), no helmet/CSP (CWE-693), `any`/`as` without validation
```ts
// GOOD
app.use(cors({ origin: ['https://app.example.com'] })); app.use(helmet());
const body = CreateUser.parse(req.body);   // zod; avoid ': any' and 'as unknown as'
```
Next.js: Route Handlers / Server Actions **have no implicit authZ** — validate session/permission in each one.

## Tools (commands)
```bash
# ESLint: eslint-plugin-security (detect-child-process, detect-eval-with-expression,
#   detect-non-literal-fs-filename, detect-unsafe-regex, detect-object-injection, ...)
#   + typescript-eslint type-aware (no-explicit-any, no-unsafe-*, no-unsafe-type-assertion)
npx eslint .
semgrep scan --config p/javascript --config p/typescript --config p/nodejs \
             --config p/react --config p/express --config p/secrets --error
njsscan --sarif -o njsscan.sarif .
npm audit --audit-level=high        # pnpm audit --audit-level high | yarn npm audit --severity high
retire --path .                     # JS libs with known CVE
```

## Supporting regex (triage — high recall, requires human review)
```
\bexec(Sync)?\s*\(   |   \bshell\s*:\s*true   |   \beval\s*\(   |   new[[:space:]]+Function\s*\(
__proto__   |   new[[:space:]]+RegExp\s*\(   |   \.innerHTML\s*=   |   dangerouslySetInnerHTML
(fetch|axios)\s*\(\s*(req\.|`?[^)]*\$\{)   |   algorithms?\s*:\s*\[?\s*['"]none['"]   |   jwt\.decode\(
createHash\(\s*['"]md5['"]   |   Math\.random\s*\(\)   |   (NEXT_PUBLIC_|VITE_)[A-Z0-9_]*(SECRET|KEY|TOKEN)
origin\s*:\s*['"]\*['"]   |   :\s*any\b   |   as[[:space:]]+unknown[[:space:]]+as   |   @ts-(ignore|nocheck)
```
