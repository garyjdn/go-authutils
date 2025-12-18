package permissions

import "gitlab.jatimprov.go.id/pharosia/auth-utils/types"

var SitePermissionMatrix = types.RolePermissionMatrix{
	"owner": {
		"site":   {"create", "read", "update", "delete"},
		"page":   {"create", "read", "update", "delete"},
		"member": {"create", "read", "update", "delete"},
	},
	"admin": {
		"site":   {"read", "update"},
		"page":   {"create", "read", "update"},
		"member": {"read"},
	},
	"member": {
		"site":   {"read"},
		"page":   {"read"},
		"member": {"read"},
	},
}
