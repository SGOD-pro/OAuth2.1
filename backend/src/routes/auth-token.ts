import { authProvider } from "../utils/auth";
import { authenticateTokenClient } from "./auth-token-auth";
import type { TokenGrantDeps } from "./auth-jwt";
import { handleRefreshTokenGrant } from "./auth-token-refresh";
import { handleAuthorizationCodeGrant } from "./auth-token-code";

export function createOAuthTokenHandler(deps: TokenGrantDeps = {}) {
    return async function handleOAuthToken(c: any): Promise<Response> {
        const authResult = await authenticateTokenClient(c);
        if (!authResult.success) {
            return authResult.response;
        }

        const { context } = authResult;
        const { params } = context;
        const grantType = params.get("grant_type");
        const refreshToken = params.get("refresh_token");

        if (grantType === "refresh_token" && refreshToken) {
            return handleRefreshTokenGrant(c, context, refreshToken, deps);
        }

        if (grantType === "authorization_code") {
            return handleAuthorizationCodeGrant(c, context, deps);
        }

        // Default fallback to Better Auth handler for any other grant types
        return (deps.authHandler ?? ((req: Request) => authProvider.handler(req)))(context.reqToForward);
    };
}

export const handleOAuthToken = createOAuthTokenHandler();
