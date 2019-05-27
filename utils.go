package rbac

func permissionPermutations(roles, operations, resources Set) []Permission {
	permissions := make([]Permission, len(roles)*len(operations)*len(resources))

	i := 0

	for role := range roles {
		for operation := range operations {
			for resource := range resources {
				permissions[i] = Permission{
					Role:      role,
					Operation: operation,
					Resource:  resource,
				}
				i++
			}
		}
	}

	return permissions
}

// Iterate current object and its all parents recursively.
func getFamily(parents StringMapSet, current string) []string {
	vals := make([]string, 1)
	vals[0] = current

	vals = append(vals, getParents(parents, current)...)

	return vals
}

// Iterate current object's all parents.
func getParents(parents StringMapSet, current string) []string {
	vals := make([]string, 0)

	for parent := range parents[current] {
		vals = append(vals, parent)

		vals = append(vals, getParents(parents, parent)...)
	}

	return vals
}
