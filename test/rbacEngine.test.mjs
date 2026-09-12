import { test, describe } from 'node:test';
import assert from 'node:assert';
import { RbacGateway } from '../src/rbacEngine.mjs';

describe('Multi-Tenant RBAC Gateway Suite', () => {
  const rbac = new RbacGateway();
  rbac.defineRole('ADMIN', ['*']);
  rbac.defineRole('EDITOR', ['documents:create', 'documents:edit']);
  rbac.defineRole('VIEWER', ['documents:read']);

  test('should allow authorized access within same tenant', () => {
    const res = rbac.authorize({
      tenantId: 'tenant-alpha',
      userTenantId: 'tenant-alpha',
      role: 'EDITOR',
      requiredPermission: 'documents:edit'
    });
    assert.strictEqual(res.allowed, true);
  });

  test('should block cross-tenant access attempts', () => {
    const res = rbac.authorize({
      tenantId: 'tenant-alpha',
      userTenantId: 'tenant-beta',
      role: 'ADMIN',
      requiredPermission: 'documents:read'
    });
    assert.strictEqual(res.allowed, false);
    assert.strictEqual(res.reason, 'CROSS_TENANT_VIOLATION');
  });
});
