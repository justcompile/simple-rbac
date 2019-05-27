package rbac

import "github.com/google/go-cmp/cmp"

var empty struct{}

type Set map[string]struct{}

func (self Set) Add(value string) {
	self[value] = empty
}

func (self Set) Contains(value string) bool {
	_, hasKey := self[value]

	return hasKey
}

func (self Set) Discard(value string) {
	delete(self, value)
}

func NewSet(vals ...string) Set {
	s := make(Set)

	for _, val := range vals {
		s.Add(val)
	}

	return s
}

func SetFromStringSlice(vals []string) Set {
	s := Set{}

	for _, val := range vals {
		s.Add(val)
	}

	return s
}

type StringMapSet map[string]Set

func (self StringMapSet) AddOrUpdate(key string, values ...string) {
	var set Set

	if value, hasKey := self[key]; hasKey {
		set = value
	} else {
		set = NewSet()
	}

	for _, v := range values {
		set.Add(v)
	}

	self[key] = set
}

func (self StringMapSet) Contains(key string) bool {
	_, hasKey := self[key]

	return hasKey
}

type AssertionParameters map[string]interface{}

type Assertion func(string, string, string, *AssertionParameters) bool

var defaultAssertion = func(role, operation, resource string, params *AssertionParameters) bool {
	return true
}

type Permission struct {
	Role, Resource, Operation string
}

type PermissionSet map[Permission]Assertion

func (self PermissionSet) Add(perm Permission, assertion *Assertion) {
	if assertion == nil {
		self[perm] = defaultAssertion
	} else {
		self[perm] = *assertion
	}
}

func (self PermissionSet) Contains(perm Permission) bool {
	permInSet := false

	for existingPerm := range self {
		if cmp.Equal(existingPerm, perm) {
			permInSet = true
			break
		}
	}

	return permInSet
}

type AccessCheck struct {
	allowed *bool
}

func (self AccessCheck) Check() bool {
	if self.allowed == nil {
		return false
	}
	return *self.allowed
}

func (self AccessCheck) isNil() bool {
	return self.allowed == nil
}

func (self AccessCheck) set(val bool) AccessCheck {
	self.allowed = &val

	return self
}
