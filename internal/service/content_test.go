package service

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// The tasks this repository publishes (content/) declare every field the
// component reads from a run, in the shape it reads.
func TestTasksDeclareWhatTheComponentReads(t *testing.T) {
	type field struct {
		Name, Type string
		Item       []struct{ Name string }
	}
	reads := map[string]map[string]string{
		taskReview:  {"summary": "text", "reads": "list", "changes": "list", "findings": "items:severity,about,why,fix"},
		taskPropose: {"rules": "items:class,method,path,why", "notes": "text"},
		taskDraft:   {"connector": "text", "notes": "text"},
	}
	for task, want := range reads {
		raw, err := os.ReadFile(filepath.Join("..", "..", "content", "connections-"+task, "component.json"))
		if err != nil {
			t.Fatal(err)
		}
		var m struct {
			Name, Output string
			Fields       []field
		}
		if err := json.Unmarshal(raw, &m); err != nil {
			t.Fatal(err)
		}
		if m.Name != "connections-"+task || m.Output != "json" {
			t.Errorf("%s: name %q output %q", task, m.Name, m.Output)
		}
		got := map[string]string{}
		for _, f := range m.Fields {
			shape := f.Type
			if shape == "" {
				shape = "text"
			}
			if shape == "items" {
				shape += ":"
				for i, it := range f.Item {
					if i > 0 {
						shape += ","
					}
					shape += it.Name
				}
			}
			got[f.Name] = shape
		}
		for name, shape := range want {
			if got[name] != shape {
				t.Errorf("%s: field %s is %q, the component reads %q", task, name, got[name], shape)
			}
		}
	}
}
