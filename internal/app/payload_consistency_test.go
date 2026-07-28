package app

// Consistency of the defense-in-depth layers.
//
// The same canonical secret set must be covered by EVERY layer that promises
// it: permissions.yaml (baseline), profiles/strict.yaml, the reviewer agent,
// settings/kiroignore, the guard binary (denyWriteRE), and the reference
// script guard-write.sh. These tests are the single source of truth against
// drift between the layers, and they enforce the profile invariant:
// strict must never be WEAKER than baseline.

import (
	"regexp"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// canonicalSecretGlobs is the canonical secret set in permissions.yaml glob form.
var canonicalSecretGlobs = []string{
	"**/.env",
	"**/.env.*",
	"**/secrets/**",
	"**/*.pem",
	"**/*.key",
	"**/id_rsa*",
	"**/id_ed25519*",
	"**/id_ecdsa*",
	"**/credentials",
	"**/*.p12",
	"**/*.pfx",
	"**/*.tfstate",
	"**/*.tfstate.*",
	"**/.npmrc",
	"**/.pypirc",
}

// canonicalSecretPaths are sample paths (one per canonical pattern family) that
// the guard binary and guard-write.sh must block.
var canonicalSecretPaths = []string{
	"config/.env",
	".env.production",
	"secrets/db-password.txt",
	"certs/server.pem",
	"keys/app.key",
	".ssh/id_rsa",
	".ssh/id_ed25519",
	".ssh/id_ecdsa",
	".aws/credentials",
	"certs/bundle.p12",
	"certs/bundle.pfx",
	"infra/terraform.tfstate",
	"infra/terraform.tfstate.backup",
	".npmrc",
	"packaging/.pypirc",
}

// selfProtectionGlobs must be denied for fs_write in every profile: the agent
// never rewrites its own guardrails.
var selfProtectionGlobs = []string{
	"**/.kiro/settings/**",
	"**/.kiro/hooks/**",
}

type consistencyRule struct {
	Capability string   `yaml:"capability"`
	Effect     string   `yaml:"effect"`
	Match      []string `yaml:"match"`
}

type consistencyRules struct {
	Rules []consistencyRule `yaml:"rules"`
}

// adminProfileSource is the Administration-scope template (deny/ask only).
// It is NOT installable via --profile; it is distributed by the organization
// (see docs/security/ENTERPRISE.md).
const adminProfileSource = "payload/global/settings/profiles/admin.yaml"

func loadRulesSource(t *testing.T, source string) consistencyRules {
	t.Helper()
	data, err := payloadFS.ReadFile(source)
	if err != nil {
		t.Fatalf("read %s: %v", source, err)
	}
	// Structural validity: same parser the installer's merge relies on.
	if _, _, err := parsePermissionsDocument(data, false); err != nil {
		t.Fatalf("%s is not a valid permissions document: %v", source, err)
	}
	var out consistencyRules
	if err := yaml.Unmarshal(data, &out); err != nil {
		t.Fatalf("parse %s: %v", source, err)
	}
	if len(out.Rules) == 0 {
		t.Fatalf("%s has no rules", source)
	}
	return out
}

func loadProfileRules(t *testing.T, profile string) consistencyRules {
	t.Helper()
	source, ok := profileSources[profile]
	if !ok {
		t.Fatalf("unknown profile: %s", profile)
	}
	return loadRulesSource(t, source)
}

// allPolicyFiles returns every permissions policy shipped in the payload: the
// installable profiles plus the Administration-scope template.
func allPolicyFiles(t *testing.T) map[string]consistencyRules {
	t.Helper()
	out := map[string]consistencyRules{"admin": loadRulesSource(t, adminProfileSource)}
	for _, name := range profileNames() {
		out[name] = loadProfileRules(t, name)
	}
	return out
}

func effectRank(effect string) int {
	switch effect {
	case "deny":
		return 3
	case "ask":
		return 2
	case "allow":
		return 1
	}
	return 0
}

// ruleIndex maps capability -> pattern -> most restrictive effect rank seen.
// Capability-wide rules (no match list) are indexed under pattern "".
func ruleIndex(rules consistencyRules) map[string]map[string]int {
	index := make(map[string]map[string]int)
	add := func(capability, pattern string, rank int) {
		if index[capability] == nil {
			index[capability] = make(map[string]int)
		}
		if rank > index[capability][pattern] {
			index[capability][pattern] = rank
		}
	}
	for _, rule := range rules.Rules {
		rank := effectRank(rule.Effect)
		if len(rule.Match) == 0 {
			add(rule.Capability, "", rank)
			continue
		}
		for _, pattern := range rule.Match {
			add(rule.Capability, pattern, rank)
		}
	}
	return index
}

// Every policy file (installable profiles + admin template) must deny read
// AND write of the canonical secret set, and carry the self-protection rules.
func TestProfilesCoverCanonicalSecrets(t *testing.T) {
	for name, rules := range allPolicyFiles(t) {
		index := ruleIndex(rules)
		for _, capability := range []string{"fs_read", "fs_write"} {
			for _, glob := range canonicalSecretGlobs {
				if index[capability][glob] != effectRank("deny") {
					t.Errorf("policy %s: %s %q must be deny", name, capability, glob)
				}
			}
		}
		for _, glob := range selfProtectionGlobs {
			if index["fs_write"][glob] != effectRank("deny") {
				t.Errorf("policy %s: self-protection fs_write deny %q missing", name, glob)
			}
		}
	}
}

// assertAtLeastBaselineRestrictions checks the profile invariant: every
// baseline deny must stay a deny, every baseline ask must be at least ask.
// (Baseline allows may be dropped — the default is ask, which is stricter.)
func assertAtLeastBaselineRestrictions(t *testing.T, name string, candidate map[string]map[string]int) {
	t.Helper()
	baseline := ruleIndex(loadProfileRules(t, "baseline"))
	for capability, patterns := range baseline {
		for pattern, rank := range patterns {
			if rank < effectRank("ask") {
				continue // allow: absence falls back to ask (stricter)
			}
			if got := candidate[capability][pattern]; got < rank {
				t.Errorf("%s is weaker than baseline for capability=%s pattern=%q: baseline=%d got=%d",
					name, capability, pattern, rank, got)
			}
		}
	}
}

// Profile invariant: strict is a superset of the baseline restrictions.
func TestStrictProfileIsSupersetOfBaseline(t *testing.T) {
	assertAtLeastBaselineRestrictions(t, "strict", ruleIndex(loadProfileRules(t, "strict")))
}

// The Administration template must carry every baseline restriction: it is
// the org-wide floor and can never be weaker than the personal baseline.
func TestAdminProfileCoversBaselineRestrictions(t *testing.T) {
	assertAtLeastBaselineRestrictions(t, "admin", ruleIndex(loadRulesSource(t, adminProfileSource)))
}

// The Administration scope only accepts deny/ask — an allow in the template
// would be invalid (and misleading) as org policy.
func TestAdminProfileOnlyDenyAsk(t *testing.T) {
	for _, rule := range loadRulesSource(t, adminProfileSource).Rules {
		if rule.Effect != "deny" && rule.Effect != "ask" {
			t.Errorf("admin template: rule capability=%s has effect %q; only deny/ask are allowed in the Administration scope",
				rule.Capability, rule.Effect)
		}
	}
}

// The guard binary must block writes/redirections to every canonical secret
// path — and must not flag ordinary source files.
func TestGuardDenyWriteCoversCanonicalSecrets(t *testing.T) {
	for _, path := range canonicalSecretPaths {
		if !matchesDenyWrite(path) {
			t.Errorf("guard denyWriteRE must block %q", path)
		}
	}
	// Windows-style separators are normalized before matching.
	for _, path := range []string{`proj\.npmrc`, `infra\terraform.tfstate`, `ssh\id_ed25519`} {
		if !matchesDenyWrite(path) {
			t.Errorf("guard denyWriteRE must block windows path %q", path)
		}
	}
	for _, path := range []string{"src/main.ts", "docs/README.md", "internal/app/guard.go"} {
		if matchesDenyWrite(path) {
			t.Errorf("guard denyWriteRE must NOT block %q", path)
		}
	}
}

// kiroignore must hide the canonical secret set from the agent's context.
func TestKiroignoreCoversCanonicalSecrets(t *testing.T) {
	data, err := payloadFS.ReadFile("payload/global/settings/kiroignore")
	if err != nil {
		t.Fatal(err)
	}
	entries := make(map[string]bool)
	for _, line := range strings.Split(string(data), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed != "" && !strings.HasPrefix(trimmed, "#") {
			entries[trimmed] = true
		}
	}
	for _, want := range []string{
		".env", ".env.*", "secrets/", "*.pem", "*.key", "*.p12", "*.pfx",
		"id_rsa*", "id_ed25519*", "id_ecdsa*", "*.tfstate", "*.tfstate.*",
		"**/credentials", ".aws/credentials", ".npmrc", ".pypirc",
	} {
		if !entries[want] {
			t.Errorf("kiroignore must contain %q", want)
		}
	}
}

// The read-only reviewer agent must deny reading the canonical secret set.
func TestReviewerAgentDeniesCanonicalSecrets(t *testing.T) {
	data, err := payloadFS.ReadFile("payload/global/agents/kiro-secops-reviewer.md")
	if err != nil {
		t.Fatal(err)
	}
	content := string(data)
	if !strings.HasPrefix(content, "---\n") {
		t.Fatal("agent is missing YAML front-matter")
	}
	rest := content[len("---\n"):]
	end := strings.Index(rest, "\n---")
	if end < 0 {
		t.Fatal("agent front-matter is not terminated")
	}
	var doc struct {
		Permissions consistencyRules `yaml:"permissions"`
	}
	if err := yaml.Unmarshal([]byte(rest[:end]), &doc); err != nil {
		t.Fatalf("parse agent front-matter: %v", err)
	}
	index := ruleIndex(doc.Permissions)
	for _, glob := range canonicalSecretGlobs {
		if index["fs_read"][glob] != effectRank("deny") {
			t.Errorf("reviewer agent: fs_read deny %q missing", glob)
		}
	}
	if index["fs_write"][""] != effectRank("deny") {
		t.Error("reviewer agent: capability-wide fs_write deny missing")
	}
}

// The reference script guard-write.sh must block the same canonical paths.
// Its POSIX ERE patterns are compatible with Go's regexp for this subset.
func TestGuardWriteScriptCoversCanonicalSecrets(t *testing.T) {
	data, err := payloadFS.ReadFile("payload/workspace/scripts/guard-write.sh")
	if err != nil {
		t.Fatal(err)
	}
	script := string(data)
	start := strings.Index(script, "deny_patterns=(")
	if start < 0 {
		t.Fatal("guard-write.sh: deny_patterns array not found")
	}
	block := script[start:]
	if end := strings.Index(block, "\n)"); end >= 0 {
		block = block[:end]
	}
	var patterns []*regexp.Regexp
	for _, line := range strings.Split(block, "\n") {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, "'") {
			continue
		}
		closing := strings.Index(trimmed[1:], "'")
		if closing < 0 {
			continue
		}
		patterns = append(patterns, regexp.MustCompile("(?i)"+trimmed[1:1+closing]))
	}
	if len(patterns) == 0 {
		t.Fatal("guard-write.sh: no deny pattern extracted")
	}
	matchesAny := func(path string) bool {
		for _, pattern := range patterns {
			if pattern.MatchString(path) {
				return true
			}
		}
		return false
	}
	for _, path := range canonicalSecretPaths {
		if !matchesAny(path) {
			t.Errorf("guard-write.sh must block %q", path)
		}
	}
	for _, path := range []string{"src/main.ts", "docs/README.md"} {
		if matchesAny(path) {
			t.Errorf("guard-write.sh must NOT block %q", path)
		}
	}
}
