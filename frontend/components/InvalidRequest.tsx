import React from 'react';
import GlassSurface from '@/components/GlassSurface';

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
      <GlassSurface
        width="100%"
        height="auto"
        borderRadius={28}
        backgroundOpacity={0.12}
        blur={12}
        saturation={1.6}
        className="w-full max-w-md mx-auto"
      >
        <div className="w-full px-8 py-10 text-center">
          <div className="mx-auto flex h-12 w-12 items-center justify-center rounded-2xl border border-white/10 bg-white/10">
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
              className="text-foreground"
            >
              <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
              <line x1="12" y1="8" x2="12" y2="12" />
              <line x1="12" y1="16" x2="12.01" y2="16" />
            </svg>
          </div>
          <p className="mt-6 text-xs uppercase tracking-[0.18em] text-muted-foreground">SWYRA Auth</p>
          <h1 className="mt-2 text-xl font-semibold text-chart-2">{title}</h1>
          <p className="mt-3 text-sm text-muted-foreground leading-6">{message}</p>
        </div>
      </GlassSurface>
    </div>
  );
};
