export function extractTargetClientId(c: any): string | null {
  const paramId = c.req.param("id") || c.req.param("clientId");
  if (paramId && typeof paramId === "string" && paramId.trim().length > 0) {
    return paramId.trim();
  }

  const path = c.req.path || "";
  const clientsMatch = path.match(/^\/api\/admin\/clients\/([^\/?#]+)/);
  if (clientsMatch && clientsMatch[1]) {
    return decodeURIComponent(clientsMatch[1]).trim();
  }
  const appMatch = path.match(/^\/api\/admin\/app\/([^\/?#]+)/);
  if (appMatch && appMatch[1]) {
    return decodeURIComponent(appMatch[1]).trim();
  }

  return null;
}
