package rbac

import (
	"fmt"

	"github.com/justcompile/simple-rbac/internal"
)

// Registry contains the Access Control List
type Registry struct {
	roles     StringMapSet
	resources StringMapSet
	allowed   PermissionSet
	denied    PermissionSet

	denialOnlyRoles Set
	children        StringMapSet
}

// AddRole adds or appends parent roles
func (self *Registry) AddRole(role string, parents ...string) {
	self.roles.AddOrUpdate(role, parents...)

	for _, parent := range parents {
		self.children.AddOrUpdate(parent, role)
	}

	if len(parents) == 0 || self.rolesAreDenyOnly(parents) {
		self.denialOnlyRoles.Add(role)
	}
}

// AddResource creates a resource or appends parents to a special resource
func (self *Registry) AddResource(resource string, parents ...string) {
	self.resources.AddOrUpdate(resource, parents...)
}

// Allow creates a rule which allows the role and it's children to operate the resource
func (self *Registry) Allow(role, operation, resource string, assertFunc *Assertion) error {
	if role == "" || !self.roles.Contains(role) {
		return fmt.Errorf("Role cannot be empty & must exist in the registry")
	}

	if resource == "" || !self.resources.Contains(resource) {
		return fmt.Errorf("Resource cannot be empty & must exist in the registry")
	}

	self.allowed.Add(
		Permission{Role: role, Operation: operation, Resource: resource},
		assertFunc,
	)

	// since we just allowed a permission, role and any children aren't
	// denied-only

	for role := range internal.Chain([]string{role}, getFamily(self.children, role)) {
		self.denialOnlyRoles.Discard(role)
	}

	return nil
}

// Deny creates a role which will deny the role and it's children from operating upon the resource
func (self *Registry) Deny(role, operation, resource string, assertFunc *Assertion) error {
	if role == "" || !self.roles.Contains(role) {
		return fmt.Errorf("Role cannot be empty & must exist in the registry")
	}

	if resource == "" || !self.resources.Contains(resource) {
		return fmt.Errorf("Resource cannot be empty & must exist in the registry")
	}

	self.denied.Add(
		Permission{Role: role, Operation: operation, Resource: resource},
		assertFunc,
	)

	return nil
}

// IsAllowed checks the role has the ability to run the specified operation on the given resource.
// If the access is denied, this method will return False; if the access
// is allowed, this method will return True; if there is not any rule
// for the access, this method will return None.
func (self *Registry) IsAllowed(role, operation, resource string, checkAllowed bool, params *AssertionParameters) (AccessCheck, error) {
	allowed := AccessCheck{}

	if role == "" || !self.roles.Contains(role) {
		return allowed, fmt.Errorf("Role cannot be empty & must exist in the registry")
	}

	if resource == "" || !self.resources.Contains(resource) {
		return allowed, fmt.Errorf("Resource cannot be empty & must exist in the registry")
	}

	roles := SetFromStringSlice(getFamily(self.roles, role))
	operations := NewSet("", operation)
	resources := SetFromStringSlice(getFamily(self.resources, resource))

	for _, permission := range permissionPermutations(roles, operations, resources) {
		if self.denied.Contains(permission) {
			if self.denied[permission](role, operation, resource, params) {
				return allowed.set(false), nil
			}
		}

		if checkAllowed && self.allowed.Contains(permission) {
			if self.allowed[permission](role, operation, resource, params) {
				allowed = allowed.set(true)
			}
		}
	}

	return allowed, nil
}

// IsAnyAllowed checks whether any of the roles have the ability to execute the operation against the resource
func (self *Registry) IsAnyAllowed(roles []string, operation, resource string, params *AssertionParameters) (AccessCheck, error) {
	var allowed AccessCheck

	for i, role := range roles {
		// if access not yet allowed and all remaining roles could
		// only deny access, short-circuit and return False
		if !allowed.Check() && self.rolesAreDenyOnly(roles[i:]) {
			ac := AccessCheck{}
			return ac.set(false), nil
		}

		var checkAllowed bool
		if allowed.isNil() {
			checkAllowed = true
		} else {
			checkAllowed = !allowed.Check()
		}

		// if another role gave access,
		// don't bother checking if this one is allowed
		isCurrentAllowed, err := self.IsAllowed(
			role,
			operation,
			resource,
			checkAllowed,
			params,
		)

		if err != nil {
			return allowed, err
		}

		if isCurrentAllowed.isNil() {
			continue
		}

		if !isCurrentAllowed.Check() {
			return isCurrentAllowed, nil
		} else if isCurrentAllowed.Check() {
			ac := AccessCheck{}
			allowed = ac.set(true)
		}
	}

	return allowed, nil
}

func (self *Registry) rolesAreDenyOnly(roles []string) bool {
	deniedRoles := make([]struct{}, 0)

	for _, role := range roles {
		if self.denialOnlyRoles.Contains(role) {
			deniedRoles = append(deniedRoles, struct{}{})
		}
	}

	return len(roles) == len(deniedRoles)
}

func NewRegistry() *Registry {
	return &Registry{
		make(StringMapSet),
		make(StringMapSet),
		make(PermissionSet),
		make(PermissionSet),
		NewSet(),
		make(StringMapSet),
	}
}
