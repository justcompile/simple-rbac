package rbac

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func boolPtr(val bool) *bool {
	return &val
}

func TestRegistryAllow(t *testing.T) {
	tests := map[string]struct {
		seed                      func(*Registry)
		role, operation, resource string
		expectedError             error
	}{
		"Returns error when role has not been set": {
			func(*Registry) {},
			"my-role",
			"run",
			"foobar",
			fmt.Errorf("Role cannot be empty & must exist in the registry"),
		},
		"Returns error when resource has not been set": {
			func(r *Registry) {
				r.AddRole("my-role")
			},
			"my-role",
			"run",
			"foobar",
			fmt.Errorf("Resource cannot be empty & must exist in the registry"),
		},
	}

	for name, test := range tests {
		reg := NewRegistry()
		test.seed(reg)

		actualError := reg.Allow(test.role, test.operation, test.resource, nil)

		assert.Equal(t, test.expectedError, actualError, name)
	}
}

func TestRegistryDeny(t *testing.T) {
	tests := map[string]struct {
		seed                      func(*Registry)
		role, operation, resource string
		expectedError             error
	}{
		"Returns error when role has not been set": {
			func(*Registry) {},
			"my-role",
			"run",
			"foobar",
			fmt.Errorf("Role cannot be empty & must exist in the registry"),
		},
		"Returns error when resource has not been set": {
			func(r *Registry) {
				r.AddRole("my-role")
			},
			"my-role",
			"run",
			"foobar",
			fmt.Errorf("Resource cannot be empty & must exist in the registry"),
		},
	}

	for name, test := range tests {
		reg := NewRegistry()
		test.seed(reg)

		actualError := reg.Deny(test.role, test.operation, test.resource, nil)

		assert.Equal(t, test.expectedError, actualError, name)
	}
}

func TestRegistryIsAllowed(t *testing.T) {
	tests := map[string]struct {
		role          string
		resource      string
		operation     string
		load          func(*Registry)
		expectedValue AccessCheck
		expectedError error
	}{
		"Returns error when role has not been set": {
			"my-role",
			"run",
			"foobar",
			func(*Registry) {},
			AccessCheck{},
			fmt.Errorf("Role cannot be empty & must exist in the registry"),
		},
		"Returns error when resource has not been set": {
			"my-role",
			"run",
			"foobar",
			func(r *Registry) {
				r.AddRole("my-role")
			},
			AccessCheck{},
			fmt.Errorf("Resource cannot be empty & must exist in the registry"),
		},
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
			nil,
		},
		"Returns true when permission is valid": {
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
			nil,
		},
		"Returns false when permission has been denied": {
			"admin",
			"server",
			"shutdown",
			func(r *Registry) {
				r.AddRole("admin")
				r.AddResource("server")
				if err := r.Deny("admin", "shutdown", "server", nil); err != nil {
					t.Fatal(err)
				}
			},
			AccessCheck{boolPtr(false)},
			nil,
		},
	}

	for name, test := range tests {
		reg := NewRegistry()

		test.load(reg)

		access, err := reg.IsAllowed(test.role, test.operation, test.resource, true, nil)
		assert.Equal(t, test.expectedError, err, name)
		assert.Equal(t, access, test.expectedValue, name)
	}
}

func TestRegistryIsAnyAllowed(t *testing.T) {
	tests := map[string]struct {
		roles         []string
		operation     string
		resource      string
		load          func(*Registry)
		expectedValue AccessCheck
		expectedError error
	}{
		// "Returns error when role does not exist": {
		// 	[]string{"my-role"},
		// 	"run",
		// 	"foobar",
		// 	func(*Registry) {},
		// 	AccessCheck{},
		// 	fmt.Errorf("Role cannot be empty & must exist in the registry"),
		// },
		// "Returns false when role has been denied": {
		// 	[]string{"my-role"},
		// 	"run",
		// 	"foobar",
		// 	func(r *Registry) {
		// 		r.AddRole("my-role")
		// 		r.AddResource("foobar")
		// 		if err := r.Deny("my-role", "run", "foobar", nil); err != nil {
		// 			t.Fatal(err)
		// 		}
		// 	},
		// 	AccessCheck{boolPtr(false)},
		// 	nil,
		// },
		// "Returns false when role does not have access": {
		// 	[]string{"my-role"},
		// 	"run",
		// 	"foobar",
		// 	func(r *Registry) {
		// 		r.AddRole("my-role")
		// 		r.AddResource("foobar")
		// 		if err := r.Deny("my-role", "delete", "foobar", nil); err != nil {
		// 			t.Fatal(err)
		// 		}
		// 	},
		// 	AccessCheck{boolPtr(false)},
		// 	nil,
		// },
		// "Returns true when role does have access": {
		// 	[]string{"my-role"},
		// 	"run",
		// 	"foobar",
		// 	func(r *Registry) {
		// 		r.AddRole("my-role")
		// 		r.AddResource("foobar")
		// 		if err := r.Allow("my-role", "run", "foobar", nil); err != nil {
		// 			t.Fatal(err)
		// 		}
		// 	},
		// 	AccessCheck{boolPtr(true)},
		// 	nil,
		// },
		// "Returns true when one role does have access": {
		// 	[]string{"role-without-access", "my-role"},
		// 	"run",
		// 	"foobar",
		// 	func(r *Registry) {
		// 		r.AddRole("my-role")
		// 		r.AddRole("role-without-access")
		// 		r.AddResource("foobar")
		// 		if err := r.Allow("my-role", "run", "foobar", nil); err != nil {
		// 			t.Fatal(err)
		// 		}
		// 	},
		// 	AccessCheck{boolPtr(true)},
		// 	nil,
		// },
		"Returns false when one role explicity denies access": {
			[]string{"role-without-access", "my-role"},
			"run",
			"foobar",
			func(r *Registry) {
				r.AddRole("my-role")
				r.AddRole("role-without-access")
				r.AddResource("foobar")
				if err := r.Deny("my-role", "run", "foobar", nil); err != nil {
					t.Fatal(err)
				}
			},
			AccessCheck{boolPtr(false)},
			nil,
		},
	}

	for name, test := range tests {
		reg := NewRegistry()

		test.load(reg)

		access, err := reg.IsAnyAllowed(test.roles, test.operation, test.resource, nil)
		assert.Equal(t, test.expectedError, err, name)
		assert.Equal(t, access, test.expectedValue, name)
	}
}
