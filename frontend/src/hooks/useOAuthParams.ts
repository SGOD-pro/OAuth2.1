import { useSearchParams } from 'react-router-dom';

function isValidClientId(value: string): boolean {
  // Accept any alphanumeric string between 20-100 chars
  return /^[a-zA-Z0-9_-]{20,100}$/.test(value);
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
    isValidClientId(clientId),
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
