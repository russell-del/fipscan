package deps

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseGradleVersionCatalog(t *testing.T) {
	input := `[versions]
spring = "3.2.1"
bouncycastle = "1.77"

[libraries]
spring-boot       = { module = "org.springframework.boot:spring-boot-starter", version.ref = "spring" }
bouncycastle-prov = { module = "org.bouncycastle:bcprov-jdk18on", version.ref = "bouncycastle" }
bouncycastle-pkix = { group  = "org.bouncycastle", name = "bcpkix-jdk18on", version = "1.77" }
jbcrypt           = { module = "org.mindrot:jbcrypt", version = "0.4" }
mockito           = "org.mockito:mockito-core:5.10.0"

[plugins]
kotlin-jvm = { id = "org.jetbrains.kotlin.jvm", version = "1.9.22" }
`
	dir := t.TempDir()
	path := filepath.Join(dir, "libs.versions.toml")
	if err := os.WriteFile(path, []byte(input), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := parseGradleVersionCatalog(path)
	if err != nil {
		t.Fatal(err)
	}

	// Index by name for easier assertions.
	byName := map[string]string{}
	for _, d := range got {
		byName[d.Name] = d.Version
	}

	wantNames := map[string]string{
		"org.springframework.boot:spring-boot-starter": "3.2.1", // version.ref resolved
		"org.bouncycastle:bcprov-jdk18on":              "1.77",  // version.ref resolved
		"org.bouncycastle:bcpkix-jdk18on":              "1.77",  // group+name inline
		"org.mindrot:jbcrypt":                          "0.4",
		"org.mockito:mockito-core":                     "5.10.0", // shorthand string
	}
	for name, ver := range wantNames {
		if byName[name] != ver {
			t.Errorf("missing or wrong version for %s: got %q want %q", name, byName[name], ver)
		}
	}
	// Plugins section must be ignored.
	if _, ok := byName["org.jetbrains.kotlin.jvm:"]; ok {
		t.Errorf("plugin coordinate must not be captured")
	}
	// Sanity check: total count should equal the libraries we declared.
	if len(got) != len(wantNames) {
		t.Errorf("got %d entries, want %d: %+v", len(got), len(wantNames), got)
	}
}

func TestParseGradleVersionCatalog_UnresolvableRef(t *testing.T) {
	// If version.ref points at a missing alias, we emit the entry with
	// an empty version (the user will see "<name>" with no version in
	// the finding). The lookup will fall through to unconstrained
	// catalog entries only — fail-safe rather than fail-loud.
	input := `[libraries]
mystery = { module = "org.mystery:lib", version.ref = "nonexistent" }
`
	dir := t.TempDir()
	path := filepath.Join(dir, "libs.versions.toml")
	_ = os.WriteFile(path, []byte(input), 0o644)
	got, _ := parseGradleVersionCatalog(path)
	if len(got) != 1 {
		t.Fatalf("got %d, want 1", len(got))
	}
	if got[0].Version != "" {
		t.Errorf("unresolvable version.ref should produce empty version, got %q", got[0].Version)
	}
}
