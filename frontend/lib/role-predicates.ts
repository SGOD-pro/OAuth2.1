export interface UserWithRole {
  role?: string | null;
  scopedClientId?: string | null;
  email?: string | null;
}

/**
 * Super Administrator predicate:
 * Strictly requires domain role "super-admin" with unscoped client assignment (null or undefined),
 * or legacy role "admin" with explicit null scope.
 * Fails closed if scopedClientId is a string or empty.
 */
export function isSuperAdminUser(user?: UserWithRole | null): boolean {
  if (!user) return false;
  const rawRole = user.role;
  const rawScope = user.scopedClientId;

  // Super-admin role must not have client scoping
  if (rawRole === 'super-admin') {
    return rawScope === null || rawScope === undefined;
  }

  // Legacy admin role strictly requires explicit null scope (never infer from missing or empty)
  if (rawRole === 'admin' && rawScope === null) {
    return true;
  }

  return false;
}

/**
 * Application Administrator predicate:
 * Requires domain role "app-admin" with valid client scoping,
 * or legacy role "admin" with a non empty string scopedClientId.
 * Super-admins can never be app-admins.
 */
export function isAppAdminUser(user?: UserWithRole | null): boolean {
  if (!user) return false;
  if (isSuperAdminUser(user)) return false;

  const rawRole = user.role;
  const rawScope = user.scopedClientId;
  if (rawRole === 'app-admin') {
    if (typeof rawScope === 'string') {
      return rawScope.trim().length > 0;
    }
    return true;
  }

  if (rawRole === 'admin' && typeof rawScope === 'string' && rawScope.trim().length > 0) {
    return true;
  }

  return false;
}

