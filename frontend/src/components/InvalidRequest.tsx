import React from 'react';
import { SilkBackground } from './SilkBackground';
import { ThemeToggle } from './ThemeToggle';

type Reason = 'missing_params' | 'invalid_client' | 'invalid_redirect';

const CONTENT: Record<Reason, { title: string; message: string }> = {
  missing_params: {
    title: 'Invalid Request',
    message:
      'Required authorization parameters are missing. Return to your application and initiate sign in from there.',
  },
  invalid_client: {
    title: 'Unknown Application',
    message:
      'This application is not registered with SWYRA Auth. Contact the application developer.',
  },
  invalid_redirect: {
    title: 'Invalid Redirect URI',
    message:
      'The redirect URI does not match what is registered for this application. This may indicate a security issue.',
  },
};

interface InvalidRequestProps {
  reason: Reason;
}

/**
 * Shown when an OAuth flow has invalid/missing parameters.
 * No back button, no retry, no form.
 * User must return to their app and start over.
 */
export const InvalidRequest: React.FC<InvalidRequestProps> = ({ reason }) => {
  const { title, message } = CONTENT[reason];

  return (
    <div className="app-container">
      <ThemeToggle />
      <div className="left-pane">
        <div className="glass-surface auth-form" style={{ textAlign: 'center' }}>
          <div style={{ marginBottom: '1.5rem' }}>
            {/* Warning shield icon */}
            <svg
              xmlns="http://www.w3.org/2000/svg"
              width="48"
              height="48"
              viewBox="0 0 24 24"
              fill="none"
              stroke="currentColor"
              strokeWidth="1.5"
              strokeLinecap="round"
              strokeLinejoin="round"
              style={{ color: 'var(--primary-color)', margin: '0 auto 1rem' }}
            >
              <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
              <line x1="12" y1="8" x2="12" y2="12" />
              <line x1="12" y1="16" x2="12.01" y2="16" />
            </svg>
          </div>
          <div className="auth-header">
            <h1>{title}</h1>
            <p style={{ lineHeight: 1.6 }}>{message}</p>
          </div>
        </div>
      </div>
      <SilkBackground />
    </div>
  );
};
