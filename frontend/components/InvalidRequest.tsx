import React from 'react';


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
    <div className="px-6 grid place-items-center min-h-dvh w-dvw">
      <div className="w-full max-w-md mx-auto">
        <div className="glass-card rounded-[22px] p-8 text-center relative overflow-hidden transition-all duration-300">
          <div className="mx-auto flex h-12 w-12 items-center justify-center rounded-2xl border border-destructive/20 bg-destructive/10 text-destructive mb-6 shadow-sm">
            <svg
              xmlns="http://www.w3.org/2000/svg"
              width="24"
              height="24"
              viewBox="0 0 24 24"
              fill="none"
              stroke="currentColor"
              strokeWidth="1.5"
              strokeLinecap="round"
              strokeLinejoin="round"
            >
              <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
              <line x1="12" y1="8" x2="12" y2="12" />
              <line x1="12" y1="16" x2="12.01" y2="16" />
            </svg>
          </div>
          <p className="mt-6 text-xs uppercase tracking-[0.18em] text-muted-foreground font-mono">NexusID</p>
          <h1 className="mt-2 text-xl font-semibold text-foreground font-heading">{title}</h1>
          <p className="mt-3 text-sm text-muted-foreground leading-relaxed">{message}</p>
        </div>
      </div>
    </div>
  );
};
