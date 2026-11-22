import { createAccessControl } from "better-auth/plugins/access";

export const accessControl = createAccessControl({
  user: ['create', 'list', 'set-role', 'ban', 'impersonate', 'impersonate-admins', 'delete', 'set-password', 'set-email', 'get', 'update'],
  session: ['list', 'revoke', 'delete']
});

export const superAdminRole = accessControl.newRole({
  user: ['create', 'list', 'set-role', 'ban', 'impersonate', 'impersonate-admins', 'delete', 'set-password', 'set-email', 'get', 'update'],
  session: ['list', 'revoke', 'delete'],
});

export const legacyAdminRole = accessControl.newRole({
  user: ['create', 'list', 'set-role', 'ban', 'impersonate', 'delete', 'set-password', 'set-email', 'get', 'update'],
  session: ['list', 'revoke', 'delete'],
});

export const appAdminRole = accessControl.newRole({
  user: [],
  session: [],
});

export const userRole = accessControl.newRole({
  user: [],
  session: [],
});

export function isSuperAdminUser(user: any): boolean {
  if (!user) return false;
  if (user.role === "super-admin") {
    return user.scopedClientId === null || user.scopedClientId === undefined;
  }
  if (user.role === "admin" && user.scopedClientId === null) {
    return true;
  }
  return false;
}
