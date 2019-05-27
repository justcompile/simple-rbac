package rbac

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func boolPtr(val bool) *bool {
	return &val
}

func TestRegistry(t *testing.T) {
	tests := map[string]struct {
		role          string
		resource      string
		operation     string
		load          func(*Registry)
		expectedValue AccessCheck
	}{
		"Returns false when no permissions found": {
			"admin",
			"server",
			"shutdown",
			func(r *Registry) {
				r.AddRole("admin")
				r.AddResource("server")
				if err := r.Allow("admin", "config", "server", nil); err != nil {
					t.Fatal(err)
				}
			},
			AccessCheck{},
		},
		"Returns true when no permissions found": {
			"admin",
			"server",
			"shutdown",
			func(r *Registry) {
				r.AddRole("admin")
				r.AddResource("server")
				if err := r.Allow("admin", "shutdown", "server", nil); err != nil {
					t.Fatal(err)
				}
			},
			AccessCheck{boolPtr(true)},
		},
	}

	for _, test := range tests {
		reg := NewRegistry()

		test.load(reg)

		access, err := reg.IsAllowed(test.role, test.operation, test.resource, true, nil)
		assert.Equal(t, err, nil)
		assert.Equal(t, access, test.expectedValue)
	}
}
