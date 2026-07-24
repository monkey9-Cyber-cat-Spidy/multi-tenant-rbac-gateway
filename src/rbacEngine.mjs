export class RbacGateway {
  constructor() {
    this.rolePermissions = new Map();
  }

  defineRole(role, permissions) {
    this.rolePermissions.set(role, new Set(permissions));
  }

  authorize({ tenantId, userTenantId, role, requiredPermission }) {
    if (tenantId !== userTenantId) {
      return { allowed: false, reason: 'CROSS_TENANT_VIOLATION' };
    }

    const perms = this.rolePermissions.get(role);
    if (!perms) {
      return { allowed: false, reason: 'ROLE_NOT_FOUND' };
    }

    if (perms.has('*') || perms.has(requiredPermission)) {
      return { allowed: true };
    }

    return { allowed: false, reason: 'INSUFFICIENT_PERMISSIONS' };
  }
}
