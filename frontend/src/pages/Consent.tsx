import React, { useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import { SilkBackground } from '../components/SilkBackground';
import { ThemeToggle } from '../components/ThemeToggle';
import { authClient } from '../lib/auth-client';

/**
 * ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 * OAuth Consent Screen
 * ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 *
 * Shown when a third-party app requests access to a user's data.
 * First-party apps with skip_consent: true bypass this entirely.
 *
 * The OAuth Provider redirects here with:
 *   ?client_id=...&scope=openid+profile+email
 */
export const Consent: React.FC = () => {
  const [searchParams] = useSearchParams();
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const clientId = searchParams.get('client_id') || 'Unknown App';
  const rawScope = searchParams.get('scope') || 'openid profile email';
  const scopes = rawScope.split(' ').filter(Boolean);

  // Human-readable scope descriptions
  const scopeDescriptions: Record<string, { label: string; icon: string }> = {
    openid: { label: 'Verify your identity', icon: '🔐' },
    profile: { label: 'Access your name and profile picture', icon: '👤' },
    email: { label: 'Read your email address', icon: '📧' },
    offline_access: { label: 'Stay signed in on your behalf', icon: '🔄' },
  };

  const handleConsent = async (accept: boolean) => {
    setLoading(true);
    setError('');

    try {
      const { error: consentError } = await authClient.oauth2.consent({
        accept,
        scope: accept ? rawScope : undefined,
      });

      if (consentError) {
        setError(consentError.message || 'Consent failed.');
        setLoading(false);
      }
      // On success, Better Auth redirects back to the consuming app automatically.
    } catch {
      setError('Something went wrong. Please try again.');
      setLoading(false);
    }
  };

  return (
    <div className="app-container">
      <ThemeToggle />
      <div className="left-pane">
        <div className="glass-surface auth-form" style={{ viewTransitionName: 'auth-form', maxWidth: '480px' }}>
          <div className="auth-header">
            <h1>Authorize Access</h1>
            <p>
              <strong style={{ color: 'var(--primary-color)' }}>{clientId}</strong> wants to access your account.
            </p>
          </div>

          {error && (
            <div className="auth-error" role="alert">
              <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg>
              {error}
            </div>
          )}

          <div className="consent-scopes">
            <p style={{ fontWeight: 600, marginBottom: '0.75rem', fontSize: '0.95rem', opacity: 0.8 }}>
              This application will be able to:
            </p>
            <ul className="scope-list">
              {scopes.map((scope) => {
                const desc = scopeDescriptions[scope] || { label: scope, icon: '📋' };
                return (
                  <li key={scope} className="scope-item">
                    <span className="scope-icon">{desc.icon}</span>
                    <span>{desc.label}</span>
                  </li>
                );
              })}
            </ul>
          </div>

          <div className="consent-actions">
            <button
              type="button"
              className="btn-primary"
              onClick={() => handleConsent(true)}
              disabled={loading}
            >
              {loading ? 'Processing...' : 'Allow Access'}
            </button>
            <button
              type="button"
              className="btn-secondary"
              onClick={() => handleConsent(false)}
              disabled={loading}
            >
              Deny
            </button>
          </div>

          <p style={{ textAlign: 'center', fontSize: '0.8rem', opacity: 0.5, marginTop: '1rem' }}>
            You can revoke access at any time from your account settings.
          </p>
        </div>
      </div>
      <SilkBackground />
    </div>
  );
};
