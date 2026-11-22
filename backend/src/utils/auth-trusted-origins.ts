import { config } from "../config";
import { isLoopbackHost, normalizeOrigin } from "./security";
import { isOriginAllowed } from "../middleware/cors";

export async function resolveTrustedOrigins(request?: Request): Promise<string[]> {
  const isProduction = config.env === "production";
  const allowDevInProd = config.allowDevClientsInProduction;

  const origins = new Set<string>();
  if (config.frontendUrl) {
    const normFrontend = normalizeOrigin(config.frontendUrl);
    if (normFrontend) origins.add(normFrontend);
  }

  // Only in development do we populate default local dev loopback origins
  if (!isProduction) {
    origins.add("http://localhost:5174");
    origins.add("http://localhost:5173");
    origins.add("http://localhost:3000");
    origins.add("http://localhost:5175");
    origins.add("http://localhost:3001");
    origins.add("http://127.0.0.1:5174");
    origins.add("http://127.0.0.1:3000");
  }

  if (request) {
    const reqOrigin = request.headers.get("origin");
    if (reqOrigin) {
      const normalized = normalizeOrigin(reqOrigin);
      if (normalized) {
        let isLoopback = false;
        try {
          isLoopback = isLoopbackHost(new URL(normalized).hostname);
        } catch {}

        if (!isProduction) {
          if (isLoopback) {
            origins.add(normalized);
          } else {
            try {
              const allowed = await isOriginAllowed(normalized);
              if (allowed) origins.add(normalized);
            } catch {}
          }
        } else {
          // In production: loopback is strictly prohibited unless explicitly configured dev mode
          if (isLoopback && !allowDevInProd) {
            // Do not trust loopback origin in production
          } else {
            try {
              const allowed = await isOriginAllowed(normalized);
              if (allowed) origins.add(normalized);
            } catch {}
          }
        }
      }
    }
  }
  return Array.from(origins);
}
