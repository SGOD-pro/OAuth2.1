import React from 'react';

export const RouteLoader: React.FC = () => {
  return (
    <div className="w-full min-h-[60vh] flex items-center justify-center">
      <div
        className="glass-surface auth-form"
        style={{ textAlign: 'center', padding: '2rem', minWidth: 280 }}
        role="status"
        aria-live="polite"
      >
        <div className="mx-auto h-9 w-9 animate-spin rounded-full border-2 border-white/30 border-t-white" />
        <p style={{ marginTop: '1rem', opacity: 0.7 }}>Loading page...</p>
      </div>
    </div>
  );
};
