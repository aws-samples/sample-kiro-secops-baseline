package app

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"strings"

	"gopkg.in/yaml.v3"
)

const (
	mgrStart                 = "# >>> kiro-secops managed (do not edit inside this block) >>>"
	mgrEnd                   = "# <<< kiro-secops managed <<<"
	managedRuleToken         = "kiro-secops-managed"
	permissionsSchemaVersion = 1
)

// managedRuleComment is the ownership comment written on each managed rule.
// It keeps the token stable (detection) and records profile + schema version (tracking).
func managedRuleComment(profile string) string {
	if profile == "" {
		profile = defaultProfile
	}
	return fmt.Sprintf("%s profile=%s schema=%d (do not edit this item)", managedRuleToken, profile, permissionsSchemaVersion)
}

// mergePermissionsData performs a structural merge of the top-level rules sequence.
// Managed rules receive an ownership comment (profile + version) for idempotent
// updates and traceability.
func mergePermissionsData(existing, managed []byte, profile string) ([]byte, error) {
	cleanExisting, err := stripLegacyManagedBlock(string(existing))
	if err != nil {
		return nil, err
	}
	doc, root, err := parsePermissionsDocument([]byte(cleanExisting), true)
	if err != nil {
		return nil, fmt.Errorf("invalid existing permissions: %w", err)
	}
	_, managedRoot, err := parsePermissionsDocument(managed, false)
	if err != nil {
		return nil, fmt.Errorf("invalid permissions payload: %w", err)
	}

	rules, err := ensureRulesSequence(root)
	if err != nil {
		return nil, err
	}
	managedRules, err := rulesSequence(managedRoot)
	if err != nil {
		return nil, err
	}

	marker := managedRuleComment(profile)
	kept := make([]*yaml.Node, 0, len(rules.Content)+len(managedRules.Content))
	for _, rule := range rules.Content {
		if !isManagedRule(rule) {
			kept = append(kept, rule)
		}
	}
	for _, rule := range managedRules.Content {
		clone := cloneYAMLNode(rule)
		// Remove any marker inherited from the payload so it is not duplicated.
		clone.HeadComment = marker
		kept = append(kept, clone)
	}
	rules.Content = kept

	var out bytes.Buffer
	enc := yaml.NewEncoder(&out)
	enc.SetIndent(2)
	if err := enc.Encode(doc); err != nil {
		return nil, fmt.Errorf("serialize permissions: %w", err)
	}
	if err := enc.Close(); err != nil {
		return nil, fmt.Errorf("finalize permissions: %w", err)
	}
	if _, _, err := parsePermissionsDocument(out.Bytes(), false); err != nil {
		return nil, fmt.Errorf("invalid resulting permissions: %w", err)
	}
	return out.Bytes(), nil
}

// detectProfileFromPermissions extracts profile=<x> from the first managed item.
func detectProfileFromPermissions(data []byte) string {
	_, root, err := parsePermissionsDocument(data, true)
	if err != nil {
		return ""
	}
	rules, err := rulesSequence(root)
	if err != nil {
		return ""
	}
	for _, rule := range rules.Content {
		comment := rule.HeadComment + " " + rule.LineComment + " " + rule.FootComment
		if !strings.Contains(comment, managedRuleToken) {
			continue
		}
		for _, field := range strings.Fields(comment) {
			if strings.HasPrefix(field, "profile=") {
				return strings.TrimPrefix(field, "profile=")
			}
		}
	}
	return ""
}

func parsePermissionsDocument(data []byte, allowEmpty bool) (*yaml.Node, *yaml.Node, error) {
	if len(bytes.TrimSpace(data)) == 0 {
		if !allowEmpty {
			return nil, nil, errors.New("empty document")
		}
		doc := &yaml.Node{Kind: yaml.DocumentNode}
		root := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
		doc.Content = []*yaml.Node{root}
		return doc, root, nil
	}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	var doc yaml.Node
	if err := dec.Decode(&doc); err != nil {
		return nil, nil, err
	}
	var extra yaml.Node
	if err := dec.Decode(&extra); err != io.EOF {
		if err == nil {
			return nil, nil, errors.New("more than one YAML document")
		}
		return nil, nil, err
	}
	if len(doc.Content) != 1 || doc.Content[0].Kind != yaml.MappingNode {
		return nil, nil, errors.New("root must be a YAML mapping")
	}
	root := doc.Content[0]
	seen := make(map[string]bool)
	for i := 0; i < len(root.Content); i += 2 {
		key := root.Content[i]
		if key.Kind != yaml.ScalarNode || key.Tag != "!!str" {
			return nil, nil, errors.New("top-level keys must be strings")
		}
		if seen[key.Value] {
			return nil, nil, fmt.Errorf("duplicate top-level key: %s", key.Value)
		}
		seen[key.Value] = true
	}
	return &doc, root, nil
}

func ensureRulesSequence(root *yaml.Node) (*yaml.Node, error) {
	for i := 0; i < len(root.Content); i += 2 {
		if root.Content[i].Value != "rules" {
			continue
		}
		value := root.Content[i+1]
		if value.Kind == yaml.ScalarNode && value.Tag == "!!null" {
			value.Kind, value.Tag, value.Value = yaml.SequenceNode, "!!seq", ""
			value.Content = nil
		}
		if value.Kind != yaml.SequenceNode {
			return nil, errors.New("permissions.rules must be a sequence")
		}
		return value, nil
	}
	key := &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: "rules"}
	value := &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
	root.Content = append(root.Content, key, value)
	return value, nil
}

func rulesSequence(root *yaml.Node) (*yaml.Node, error) {
	for i := 0; i < len(root.Content); i += 2 {
		if root.Content[i].Value == "rules" {
			value := root.Content[i+1]
			if value.Kind != yaml.SequenceNode {
				return nil, errors.New("payload permissions.rules must be a sequence")
			}
			return value, nil
		}
	}
	return nil, errors.New("payload permissions does not contain rules")
}

func isManagedRule(node *yaml.Node) bool {
	return strings.Contains(node.HeadComment, managedRuleToken) ||
		strings.Contains(node.LineComment, managedRuleToken) ||
		strings.Contains(node.FootComment, managedRuleToken)
}

func cloneYAMLNode(node *yaml.Node) *yaml.Node {
	clone := *node
	clone.Content = make([]*yaml.Node, len(node.Content))
	for i, child := range node.Content {
		clone.Content[i] = cloneYAMLNode(child)
	}
	return &clone
}

func stripLegacyManagedBlock(s string) (string, error) {
	start := strings.Index(s, mgrStart)
	end := strings.Index(s, mgrEnd)
	if start < 0 && end < 0 {
		return s, nil
	}
	if start < 0 || end < 0 || end < start {
		return "", errors.New("legacy managed block is incomplete")
	}
	end += len(mgrEnd)
	return s[:start] + strings.TrimPrefix(s[end:], "\n"), nil
}

// mergeKiroignoreData replaces only the explicitly managed block and keeps the
// order of the payload's negations. Entries already kept by the user are not duplicated.
func mergeKiroignoreData(existing, managed []byte) ([]byte, error) {
	base, err := stripLegacyManagedBlock(string(existing))
	if err != nil {
		return nil, err
	}
	present := make(map[string]bool)
	for _, line := range strings.Split(base, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed != "" && !strings.HasPrefix(trimmed, "#") {
			present[trimmed] = true
		}
	}
	add := make([]string, 0)
	for _, line := range strings.Split(string(managed), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") || present[trimmed] {
			continue
		}
		add = append(add, line)
		present[trimmed] = true
	}
	base = strings.TrimRight(base, "\n")
	if len(add) == 0 {
		if base == "" {
			return nil, nil
		}
		return []byte(base + "\n"), nil
	}
	var out strings.Builder
	if base != "" {
		out.WriteString(base)
		out.WriteString("\n\n")
	}
	out.WriteString(mgrStart)
	out.WriteByte('\n')
	for _, line := range add {
		out.WriteString(line)
		out.WriteByte('\n')
	}
	out.WriteString(mgrEnd)
	out.WriteByte('\n')
	return []byte(out.String()), nil
}
