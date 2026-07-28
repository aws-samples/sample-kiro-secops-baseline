# Review reference — Python

Vulnerability patterns (BAD→GOOD), tool rules, and supporting regex.
Based on: OWASP Top 10 2025 + Cheat Sheets, CWE (MITRE), Bandit/Ruff/Semgrep.

## Vulnerabilities (BAD → GOOD)

### Command injection — CWE-78 / A05 · bandit B602/B605, ruff S602
```python
# BAD
os.system(f"ping {host}"); subprocess.run(cmd, shell=True)
# GOOD
subprocess.run(["ping", "-c", "1", host], shell=False)
```

### Insecure deserialization — CWE-502 / A08 · B301 pickle, B506 yaml.load
```python
# BAD
pickle.loads(data); yaml.load(data)
# GOOD
json.loads(data); yaml.safe_load(data)
```

### SSTI / eval / exec — CWE-94/1336 / A05 · B307 eval, B701 jinja2
```python
# BAD
eval(expr); render_template_string("Hello " + name)
# GOOD
ast.literal_eval(expr); render_template("hello.html", name=name)   # autoescape on
```

### SQL injection — CWE-89 / A05 · B608
```python
# BAD
cur.execute(f"SELECT * FROM u WHERE id={uid}")
# GOOD
cur.execute("SELECT * FROM u WHERE id=%s", (uid,))
```

### Path traversal / zip-tar slip — CWE-22 / A01 · B202 tarfile
```python
# BAD
tar.extractall(path); open(os.path.join(base, user_path))
# GOOD
tar.extractall(path, filter="data")                 # py3.12+
p = os.path.realpath(os.path.join(base, user_path))
if not p.startswith(os.path.realpath(base) + os.sep): raise ValueError("traversal")
```

### XXE — CWE-611 / A02 · B313-B320
```python
# BAD
import xml.etree.ElementTree as ET; ET.fromstring(xml)
# GOOD
from defusedxml.ElementTree import fromstring; fromstring(xml)
```

### SSRF — CWE-918 / A01 · B310
```python
# BAD
requests.get(user_url)
# GOOD: host/scheme allowlist; block private/link-local IP (169.254.169.254); no redirects
```

### Crypto / secrets — CWE-327/330/295/798 / A04 · B303 md5, B311 random, B501 verify, B105 pwd
```python
# BAD
hashlib.md5(pw); random.random(); requests.get(u, verify=False); API_KEY = "sk-..."
# GOOD
argon2.hash(pw); secrets.token_urlsafe(); verify=True; os.environ["API_KEY"]
```

### Misc
DEBUG=True in prod (CWE-489); `assert` for a security check (CWE-703, removed with -O);
`tempfile.mktemp` (CWE-377 → use `mkstemp`); CORS `*` (CWE-942).

## Tools (commands)
```bash
bandit -r . -ll                 # MEDIUM+; -lll -iii = strict gate; -f sarif for code scanning
semgrep scan --config p/python --config p/flask --config p/django --config p/secrets --error
ruff check --select S .         # flake8-bandit (S) — fast, complements (does not replace) Bandit
pip-audit                       # SCA (PyPI Advisory DB / OSV); or: safety scan
gitleaks detect --no-git --redact --source .
```

## Supporting regex (fast gate — human triage; source of truth = bandit/gitleaks)
```
os\.system\(   |   subprocess\.\w+\([^)]*shell\s*=\s*True
\b(eval|exec)\s*\(   |   (c?pickle|marshal)\.(load|loads)\s*\(   |   yaml\.load\s*\(
\.execute\(\s*(f["']|.*%|.*\.format\(|.*\+)          # SQLi
hashlib\.(md5|sha1)\(   |   verify\s*=\s*False   |   tempfile\.mktemp\(
DEBUG\s*=\s*True   |   \.extractall\(
```
