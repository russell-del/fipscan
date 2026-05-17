package deps

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseGradle(t *testing.T) {
	// Cover the syntactic variations we care about + things we should
	// deliberately skip (project / file deps, comments).
	input := `plugins {
    id 'java'
}

dependencies {
    implementation 'org.bouncycastle:bcprov-jdk18on:1.77'
    api "org.bouncycastle:bcpkix-jdk18on:1.77"
    implementation("org.mindrot:jbcrypt:0.4")
    runtimeOnly 'commons-codec:commons-codec:1.16.0'
    testImplementation 'junit:junit:4.13.2'

    // Should NOT match
    implementation project(':my-module')
    implementation files('libs/x.jar')
    // implementation 'org.evil:do-not-flag:1.0'
}
`

	dir := t.TempDir()
	path := filepath.Join(dir, "build.gradle")
	if err := os.WriteFile(path, []byte(input), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := parseGradle(path)
	if err != nil {
		t.Fatal(err)
	}

	wantNames := map[string]string{
		"org.bouncycastle:bcprov-jdk18on": "1.77",
		"org.bouncycastle:bcpkix-jdk18on": "1.77",
		"org.mindrot:jbcrypt":             "0.4",
		"commons-codec:commons-codec":     "1.16.0",
		"junit:junit":                     "4.13.2",
	}
	mustNotMatch := []string{"org.evil:do-not-flag", "my-module", "libs/x.jar"}

	if len(got) != len(wantNames) {
		t.Errorf("got %d deps, want %d: %+v", len(got), len(wantNames), got)
	}
	gotNames := map[string]string{}
	for _, d := range got {
		gotNames[d.Name] = d.Version
	}
	for name, ver := range wantNames {
		if gotNames[name] != ver {
			t.Errorf("missing or wrong version for %s: got %q want %q", name, gotNames[name], ver)
		}
	}
	for _, banned := range mustNotMatch {
		for _, d := range got {
			if d.Name == banned {
				t.Errorf("falsely matched %q (should be skipped)", banned)
			}
		}
	}
}

func TestParseGradleKotlinDSL(t *testing.T) {
	input := `dependencies {
    implementation("org.bouncycastle:bcprov-jdk18on:1.77")
    testImplementation("org.junit.jupiter:junit-jupiter:5.10.0")
    implementation(platform("org.springframework.boot:spring-boot-dependencies:3.2.1"))
}
`
	dir := t.TempDir()
	path := filepath.Join(dir, "build.gradle.kts")
	if err := os.WriteFile(path, []byte(input), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := parseGradle(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Fatalf("got %d deps, want 3: %+v", len(got), got)
	}
}
