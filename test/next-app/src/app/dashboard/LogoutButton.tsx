'use client';

import React, { useState } from 'react';

export function LogoutButton({ issuer }: { issuer: string }) {
  const [loading, setLoading] = useState(false);

  const handleLogout = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);

    try {
      // 1. Sign out of IDP
      await fetch(`${issuer}/api/auth/sign-out`, {
        method: 'POST',
        credentials: 'include',
      }).catch(() => {});

      // 2. Sign out locally
      await fetch('/api/auth/logout', {
        method: 'POST',
      });
      
      // Redirect to home
      window.location.href = '/';
    } catch (err) {
      setLoading(false);
    }
  };

  return (
    <form onSubmit={handleLogout}>
      <button
        type="submit"
        disabled={loading}
        className="bg-[#161b22] hover:bg-rose-500/20 hover:text-rose-400 border border-[#30363d] hover:border-rose-500/40 text-xs font-mono text-neutral-300 px-4 py-2 rounded-xl transition-all cursor-pointer disabled:opacity-50"
      >
        {loading ? 'Signing Out...' : 'Sign Out Session'}
      </button>
    </form>
  );
}
