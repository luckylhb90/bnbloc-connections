package service

import (
	"net/http"
	"strings"
	"testing"
)

// The Connections page lists the organization's own systems and outside
// services apart, and offers each connector's examples to copy.
func TestConnectionsPageGroupsAndSuggests(t *testing.T) {
	fx := newFixture(t)
	own := issues()
	own.Internal, own.Examples = true, []string{"List my open issues due this week"}
	fx.addConnector(own)
	out := issues()
	out.Name, out.DisplayName, out.Hosts = "mail", "Mail", []string{"mail.example.net"}
	fx.addConnector(out)
	body := fx.page(false, http.MethodGet, "/pages/connections", nil).Body.String()
	company, external := strings.Index(body, "Company systems"), strings.Index(body, "External services")
	issuesAt, mailAt := strings.Index(body, `id="issues"`), strings.Index(body, `id="mail"`)
	if company < 0 || external < 0 || !(company < issuesAt && issuesAt < external && external < mailAt) {
		t.Fatalf("groups: company %d issues %d external %d mail %d", company, issuesAt, external, mailAt)
	}
	if !strings.Contains(body, `data-copy="List my open issues due this week"`) {
		t.Fatalf("the example is not offered:\n%s", body)
	}
}
