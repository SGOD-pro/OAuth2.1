import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { authClient } from '@/lib/auth-client';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Separator } from '@/components/ui/separator';
import { toast } from 'sonner';

type Mode = 'totp' | 'backup';

export const AdminTwoFactor: React.FC = () => {
  const [code, setCode] = useState('');
  const [mode, setMode] = useState<Mode>('totp');
  const [loading, setLoading] = useState(false);
  const navigate = useNavigate();

  const handleVerify = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);

    if (mode === 'totp') {
      const { error: err } = await authClient.twoFactor.verifyTotp({ code });
      if (err) {
        toast.error(err.message || 'Invalid code. Check your authenticator app.');
        setLoading(false);
        return;
      }
    } else {
      const { error: err } = await authClient.twoFactor.verifyBackupCode({ code });
      if (err) {
        toast.error(err.message || 'Invalid backup code.');
        setLoading(false);
        return;
      }
    }

    toast.success('Verification successful');
    navigate('/admin', { replace: true, viewTransition: true });
  };

  const toggleMode = () => {
    setCode('');
    setMode((m) => (m === 'totp' ? 'backup' : 'totp'));
  };

  return (
    <div className="w-full h-dvh px-6 grid place-items-center relative">
      <div className="fixed inset-0 top-0 left-0 bg-mesh-warm dark:bg-mesh-cool bg-noise -z-10" />
      
      <div className="w-full max-w-md mx-auto">
        <div className="glass-card rounded-[22px] p-8 w-full transition-all duration-300 relative overflow-hidden">
          <div className="text-left z-10 relative">
            <div className="flex items-center gap-3 mb-6">
              <div className="h-10 w-10 rounded-2xl bg-primary flex items-center justify-center text-primary-foreground shadow-sm">
                <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><rect x="3" y="11" width="18" height="11" rx="2" ry="2" /><path d="M7 11V7a5 5 0 0 1 10 0v4" /></svg>
              </div>
              <div>
                <p className="text-xs uppercase tracking-[0.18em] text-primary font-mono">Security</p>
                <h1 className="text-xl font-semibold text-foreground font-heading">
                  {mode === 'totp' ? 'Two-Factor Verification' : 'Backup Code Entry'}
                </h1>
              </div>
            </div>

            <div className="animate-in fade-in slide-in-from-bottom-2 duration-300">
              <p className="text-sm text-muted-foreground mb-6 leading-relaxed">
                {mode === 'totp'
                  ? 'Enter the 6-digit code from your authenticator app to continue.'
                  : 'Enter one of your saved backup codes to regain access.'}
              </p>
              
              <form onSubmit={handleVerify} className="space-y-4">
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
                    className={mode === 'totp' ? 'text-center text-lg tracking-widest font-mono' : ''}
                  />
                </div>
                <Button type="submit" className="w-full rounded-full mt-2" disabled={loading || !code}>
                  {loading ? 'Verifying…' : 'Verify Identity'}
                </Button>
              </form>
            </div>

            <div className="my-6 flex items-center gap-4">
              <Separator className="flex-1" />
              <span className="text-[10px] uppercase tracking-[0.2em] text-muted-foreground font-mono">or</span>
              <Separator className="flex-1" />
            </div>

            <button
              type="button"
              onClick={toggleMode}
              className="w-full text-center text-sm font-medium text-muted-foreground hover:text-foreground transition-colors"
            >
              {mode === 'totp' ? 'Use a backup code instead' : 'Use authenticator app instead'}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
