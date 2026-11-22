import { authProvider } from "../utils/auth";
import { authenticateTokenClient } from "./auth-token-auth";
import { handleRefreshTokenGrant } from "./auth-token-refresh";
import { handleAuthorizationCodeGrant } from "./auth-token-code";

export async function handleOAuthToken(c: any): Promise<Response> {
    const authResult = await authenticateTokenClient(c);
    if (!authResult.success) {
        return authResult.response;
    }

    const { context } = authResult;
    const { params } = context;
    const grantType = params.get("grant_type");
    const refreshToken = params.get("refresh_token");

    if (grantType === "refresh_token" && refreshToken) {
        return handleRefreshTokenGrant(c, context, refreshToken);
    }

    if (grantType === "authorization_code") {
        return handleAuthorizationCodeGrant(c, context);
    }

    // Default fallback to Better Auth handler for any other grant types
    return authProvider.handler(context.reqToForward);
}
