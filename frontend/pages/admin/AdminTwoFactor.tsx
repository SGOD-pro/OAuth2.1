import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { authClient } from '@/lib/auth-client';
import GlassSurface from '@/components/GlassSurface';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Separator } from '@/components/ui/separator';

type Mode = 'totp' | 'backup';

export const AdminTwoFactor: React.FC = () => {
  const [code, setCode] = useState('');
  const [mode, setMode] = useState<Mode>('totp');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const navigate = useNavigate();

  const handleVerify = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError('');

    if (mode === 'totp') {
      const { error: err } = await authClient.twoFactor.verifyTotp({ code });
      if (err) {
        setError(err.message || 'Invalid code. Check your authenticator app.');
        setLoading(false);
        return;
      }
    } else {
      const { error: err } = await authClient.twoFactor.verifyBackupCode({ code });
      if (err) {
        setError(err.message || 'Invalid backup code.');
        setLoading(false);
        return;
      }
    }

    navigate('/admin', { replace: true, viewTransition: true });
  };

  const toggleMode = () => {
    setCode('');
    setError('');
    setMode((m) => (m === 'totp' ? 'backup' : 'totp'));
  };

  return (
    <div className="w-full h-dvh px-6 grid place-items-center">
      <GlassSurface
        width="100%"
        height="auto"
        borderRadius={28}
        backgroundOpacity={0.12}
        blur={12}
        saturation={1.6}
        className="w-full max-w-md mx-auto"
      >
        <div className="w-full px-8 py-10 text-left">
          <p className="text-xs uppercase tracking-[0.18em] text-chart-1">SWYRA Admin</p>
          <h1 className="mt-3 text-2xl font-semibold text-foreground">
            {mode === 'totp' ? 'Two-factor verification' : 'Backup code'}
          </h1>
          <p className="mt-2 text-sm text-muted-foreground">
            {mode === 'totp'
              ? 'Enter the 6-digit code from your authenticator app.'
              : 'Enter one of your saved backup codes.'}
          </p>

          {error && (
            <div
              className="mt-6 rounded-2xl border border-destructive/30 bg-destructive/10 px-4 py-3 text-sm text-destructive"
              role="alert"
            >
              {error}
            </div>
          )}

          <form onSubmit={handleVerify} className="mt-6 space-y-4">
            <div className="space-y-2">
              <label htmlFor="2fa-code" className="text-sm font-medium text-foreground">
                {mode === 'totp' ? '6-digit code' : 'Backup code'}
              </label>
              <Input
                id="2fa-code"
                type="text"
                inputMode={mode === 'totp' ? 'numeric' : 'text'}
                autoComplete="one-time-code"
                placeholder={mode === 'totp' ? '000000' : 'xxxxxxxx-xxxx'}
                maxLength={mode === 'totp' ? 6 : 20}
                required
                value={code}
                onChange={(e) => setCode(e.target.value.trim())}
                disabled={loading}
              />
            </div>
            <Button type="submit" className="w-full" disabled={loading}>
              {loading ? 'Verifying…' : 'Verify'}
            </Button>
          </form>

          <div className="my-6 flex items-center gap-4">
            <Separator className="flex-1" />
            <span className="text-[11px] uppercase tracking-[0.2em] text-muted-foreground">or</span>
            <Separator className="flex-1" />
          </div>

          <button
            type="button"
            onClick={toggleMode}
            className="w-full text-center text-sm text-muted-foreground hover:text-foreground transition-colors"
          >
            {mode === 'totp' ? 'Use a backup code instead' : 'Use authenticator app instead'}
          </button>
        </div>
      </GlassSurface>
    </div>
  );
};
