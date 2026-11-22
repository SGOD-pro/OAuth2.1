export type DomainRole = "super-admin" | "app-admin" | "user";

export function isSuperAdmin(user: any): boolean {
  if (!user) return false;
  if (user.role === "super-admin") {
    // Super admin role must not have client scoping (null or undefined only; empty string or any other string fails closed)
    return user.scopedClientId === null || user.scopedClientId === undefined;
  }
  // Legacy role: "admin" strictly requires explicit null scope (never infer from missing/undefined/empty)
  if (user.role === "admin" && user.scopedClientId === null) {
    return true;
  }
  return false;
}

export function isAppAdmin(user: any): boolean {
  if (!user) return false;
  if (isSuperAdmin(user)) return false;
  if (user.role === "app-admin") {
    if (typeof user.scopedClientId === "string") {
      return user.scopedClientId.trim().length > 0;
    }
    return true;
  }
  if (user.role === "admin" && typeof user.scopedClientId === "string" && user.scopedClientId.trim().length > 0) {
    return true;
  }
  return false;
}

export function isAnyAdmin(user: any): boolean {
  return isSuperAdmin(user) || isAppAdmin(user);
}
