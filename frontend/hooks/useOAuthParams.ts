import { useSearchParams } from 'react-router-dom';

function isValidClientId(value: string): boolean {
  // Accept any alphanumeric string between 20-100 chars
  return /^[a-zA-Z0-9_-]{20,100}$/.test(value);
}

function isValidRedirectUri(uri: string | null): boolean {
  if (!uri) return false;
  try {
    const url = new URL(uri);
    return ['http:', 'https:'].includes(url.protocol);
  } catch {
    return false;
  }
}

export function useOAuthParams() {
  const [params] = useSearchParams();

  const clientId            = params.get('client_id');
  const redirectUri         = params.get('redirect_uri');
  const state               = params.get('state');
  const codeChallenge       = params.get('code_challenge');
  const codeChallengeMethod = params.get('code_challenge_method');

  const isValid = Boolean(
    clientId &&
    redirectUri &&
    state &&
    codeChallenge &&
    codeChallengeMethod === 'S256' &&
    isValidClientId(clientId) &&
    isValidRedirectUri(redirectUri),
  );

  return {
    clientId,
    redirectUri,
    state,
    codeChallenge,
    codeChallengeMethod,
    isValid,
  };
}
