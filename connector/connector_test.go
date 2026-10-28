package connector

import (
	"net/url"
	"testing"
)

func sample() Connector {
	return Connector{
		Name: "issues", DisplayName: "Issues", Purpose: "Bugs and tasks", Hosts: []string{"issues.example.com"},
		Connect: Connect{Kind: KindAPIKey, APIKey: &APIKey{In: "header", Name: "X-Api-Key"}},
		Policy: Policy{
			Read:  []Rule{{Paths: []string{"/api/**"}}, {Methods: []string{"POST"}, Paths: []string{"/api/search"}, Body: `^\s*\{`}},
			Write: []Rule{{Methods: []string{"POST", "PUT", "DELETE"}, Paths: []string{"/api/issue/*", "/api/issue"}}},
		},
		ExpiredWhen: []Expired{{Status: 302, LocationContains: "/login"}},
	}
}

func TestValidateAndClassify(t *testing.T) {
	c := sample()
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		method, path, body, want string
	}{
		{"GET", "/api/issue/7", "", Read},
		{"GET", "/api", "", Read},
		{"POST", "/api/search", `{"q":"x"}`, Read},
		{"POST", "/api/search", `q=x`, ""},
		{"POST", "/api/issue", `{}`, Write},
		{"DELETE", "/api/issue/7", "", Write},
		{"DELETE", "/api/issue/7/comments", "", ""},
		{"GET", "/admin", "", ""},
	} {
		if got := c.Classify(tc.method, tc.path, []byte(tc.body)); got != tc.want {
			t.Errorf("%s %s %q = %q, want %q", tc.method, tc.path, tc.body, got, tc.want)
		}
	}
	if !c.IsExpired(302, "https://issues.example.com/login?next=/", nil) || c.IsExpired(302, "https://x/other", nil) {
		t.Error("expiredWhen")
	}
	if got := c.CredentialHeaders(); got[len(got)-1] != "X-Api-Key" {
		t.Errorf("credential headers = %v", got)
	}
}

func TestValidateRefuses(t *testing.T) {
	for name, mutate := range map[string]func(*Connector){
		"bad name":      func(c *Connector) { c.Name = "Issues" },
		"wildcard host": func(c *Connector) { c.Hosts = []string{"*.example.com"} },
		"address host":  func(c *Connector) { c.Hosts = []string{"10.0.0.1"} },
		"no read rule":  func(c *Connector) { c.Policy.Read = nil },
		"two connects":  func(c *Connector) { c.Connect.OAuth2 = &OAuth2{} },
		"http oauth": func(c *Connector) {
			c.Connect = Connect{Kind: KindOAuth2, OAuth2: &OAuth2{Issuer: "http://idp.example.com"}}
		},
		"proxy env":         func(c *Connector) { c.CLIEnv = map[string]string{"HTTPS_PROXY": "x"} },
		"bad regexp":        func(c *Connector) { c.Policy.Read[1].Body = "(" },
		"blank example":     func(c *Connector) { c.Examples = []string{" "} },
		"two-line example":  func(c *Connector) { c.Examples = []string{"list\nmine"} },
		"too many examples": func(c *Connector) { c.Examples = []string{"a", "b", "c", "d", "e", "f"} },
	} {
		c := sample()
		mutate(&c)
		if c.Validate() == nil {
			t.Errorf("%s passes", name)
		}
	}
}

func TestGlob(t *testing.T) {
	for _, tc := range []struct {
		p, s string
		ok   bool
	}{
		{"/**", "/", true}, {"/**", "/a/b", true}, {"/a/*", "/a/b", true}, {"/a/*", "/a/b/c", false},
		{"/a/**/z", "/a/z", true}, {"/a/**/z", "/a/b/c/z", true}, {"/a/**/z", "/a/b/c", false}, {"/a", "/a/", true},
	} {
		if Glob(tc.p, tc.s) != tc.ok {
			t.Errorf("Glob(%q, %q) = %v", tc.p, tc.s, !tc.ok)
		}
	}
}

// A path a server may read otherwise than the policy is refused, in every
// encoding; plain paths, encoded spaces and ids pass.
func TestCheckPathRefusesAmbiguousPaths(t *testing.T) {
	for _, p := range []string{
		"/api/../admin/users", "/api/./x", "/api/%2e%2e/admin", "/api/%2E%2E/admin", "/api/.%2e/admin", "/api/%252e%252e/admin",
		"/api/..;/admin", "/api/%2e%2e;x/admin", "/api/a%2fb", "/api/a%2Fb", "/api/a%252fb", "/api/a%5cb", "/api/a\\b", "/api/%5c..%5cadmin",
	} {
		u, err := url.Parse("https://example.com" + p)
		if err != nil {
			continue // not even a URL: refused before the policy
		}
		if CheckPath(u) == nil {
			t.Errorf("%s passed", p)
		}
	}
	for _, p := range []string{"/api/issue/1", "/api/search%20this", "/wiki/A%20page;v=2", "/api/...", "/api/.hidden", "/"} {
		u, _ := url.Parse("https://example.com" + p)
		if err := CheckPath(u); err != nil {
			t.Errorf("%s refused: %v", p, err)
		}
	}
}
