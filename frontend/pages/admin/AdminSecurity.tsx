import React, { useState, useEffect } from 'react';
import { AdminLayout } from './AdminLayout';
import { authClient, useSession } from '@/lib/auth-client';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Card, CardContent } from '@/components/ui/card';
import { toast } from 'sonner';
import { QRCodeSVG } from 'qrcode.react';

type SetupStep = 'idle' | 'qr' | 'backup-codes' | 'done' | 'disable-prompt';

export const AdminSecurity: React.FC = () => {
  const { data: session, refetch, isPending } = useSession();
  const isTwoFactorEnabled = !!session?.user?.twoFactorEnabled;

  const [password, setPassword] = useState('');
  const [totpUri, setTotpUri] = useState('');
  const [backupCodes, setBackupCodes] = useState<string[]>([]);
  const [confirmCode, setConfirmCode] = useState('');
  const [step, setStep] = useState<SetupStep>('idle');
  const [loading, setLoading] = useState(false);

  // Strictly check status on mount and sync state
  useEffect(() => {
    if (isPending) return; // Wait for session to load
    
    if (isTwoFactorEnabled) {
      setStep('done');
    } else {
      setStep('idle');
    }
  }, [isTwoFactorEnabled, isPending]);

  const handleEnable = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);

    // This gets the QR code and manual key
    const { data, error: err } = await authClient.twoFactor.enable({ password });
    if (err || !data) {
      toast.error(err?.message || 'Failed to start 2FA setup. Check your password.');
      setLoading(false);
      return;
    }

    setTotpUri(data.totpURI);
    setBackupCodes(data.backupCodes);
    setStep('qr');
    setLoading(false);
  };

  const handleConfirm = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);

    // Call Better Auth verification endpoint to finalize setup
    const response = await authClient.twoFactor.verifyTotp({ code: confirmCode });
    
    // Debugging Step
    console.log('[DEBUG] 2FA Verify Response:', response);

    if (response.error) {
      toast.error(response.error.message || 'Invalid code. Make sure your device clock is accurate.');
      setLoading(false);
      return;
    }

    setStep('backup-codes');
    setLoading(false);
    
    // Refresh session so the UI updates to the "Enabled" state
    await refetch();
  };

  const handleDisable = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);

    const { error: err } = await authClient.twoFactor.disable({ password });
    if (err) {
      toast.error(err.message || 'Failed to disable 2FA. Check your password.');
      setLoading(false);
      return;
    }

    toast.success('Two-factor authentication disabled.');
    setPassword('');
    setStep('idle');
    setLoading(false);
    
    await refetch();
  };

  const manualKey = totpUri
    ? (new URLSearchParams(totpUri.split('?')[1] ?? '').get('secret') ?? '')
    : '';

  // Show a loading state while fetching session
  if (isPending) {
    return (
      <AdminLayout>
        <div className="flex justify-center items-center h-40">
          <div className="animate-spin h-8 w-8 border-4 border-primary border-t-transparent rounded-full"></div>
        </div>
      </AdminLayout>
    );
  }

  return (
    <AdminLayout>
      <div className="mb-8">
        <h1 className="text-3xl font-semibold text-foreground font-heading">Security</h1>
        <p className="mt-2 text-sm text-muted-foreground">
          Enable and manage two-factor authentication for your admin account.
        </p>
      </div>

      <div className="max-w-xl">
        <Card className="bg-card/50 backdrop-blur-md border-border/50 shadow-sm overflow-hidden">
          <CardContent className="p-8">
            
            {step === 'idle' && (
              <div className="animate-in fade-in slide-in-from-bottom-2 duration-300">
                <div className="flex items-center gap-4 mb-6">
                  <div className="h-12 w-12 rounded-2xl bg-primary/10 flex items-center justify-center text-primary">
                    <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><rect x="3" y="11" width="18" height="11" rx="2" ry="2" /><path d="M7 11V7a5 5 0 0 1 10 0v4" /></svg>
                  </div>
                  <div>
                    <h2 className="text-lg font-semibold text-foreground">Enable 2FA</h2>
                    <p className="text-sm text-muted-foreground">
                      Enhance your account security with an authenticator app.
                    </p>
                  </div>
                </div>
                
                <form onSubmit={handleEnable} className="space-y-4">
                  <div className="space-y-2">
                    <label htmlFor="sec-password" className="text-sm font-medium text-foreground">
                      Confirm your password to start
                    </label>
                    <Input
                      id="sec-password"
                      type="password"
                      placeholder="••••••••"
                      required
                      value={password}
                      onChange={(e) => setPassword(e.target.value)}
                      disabled={loading}
                      className="bg-background/50"
                    />
                  </div>
                  <Button type="submit" className="w-full rounded-full" disabled={loading}>
                    {loading ? 'Generating...' : 'Set up Two-Factor Authentication'}
                  </Button>
                </form>
              </div>
            )}

            {step === 'qr' && (
              <div className="animate-in fade-in slide-in-from-bottom-2 duration-300">
                <div className="flex items-center gap-4 mb-6">
                  <div className="h-12 w-12 rounded-2xl bg-primary/10 flex items-center justify-center text-primary">
                    <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M3 7V5a2 2 0 0 1 2-2h2" /><path d="M17 3h2a2 2 0 0 1 2 2v2" /><path d="M21 17v2a2 2 0 0 1-2 2h-2" /><path d="M7 21H5a2 2 0 0 1-2-2v-2" /><rect x="7" y="7" width="10" height="10" rx="1" ry="1" /></svg>
                  </div>
                  <div>
                    <h2 className="text-lg font-semibold text-foreground">Scan QR Code</h2>
                    <p className="text-sm text-muted-foreground">
                      Use Google or Microsoft Authenticator to scan this code.
                    </p>
                  </div>
                </div>

                <div className="mt-6 flex justify-center bg-white p-4 rounded-2xl max-w-fit mx-auto mb-6 shadow-sm border border-border">
                  <QRCodeSVG
                    value={totpUri}
                    size={180}
                    level="H"
                    className="rounded-sm"
                  />
                </div>

                {manualKey && (
                  <div className="rounded-xl border border-border/50 bg-muted/30 px-4 py-3 mb-6 text-center">
                    <p className="text-[10px] uppercase tracking-widest text-muted-foreground mb-1">Manual entry key</p>
                    <code className="text-sm font-mono text-primary font-medium break-all">{manualKey}</code>
                  </div>
                )}

                <form onSubmit={handleConfirm} className="space-y-4">
                  <div className="space-y-2">
                    <label htmlFor="totp-confirm" className="text-sm font-medium text-foreground">
                      Enter the 6-digit code
                    </label>
                    <Input
                      id="totp-confirm"
                      type="text"
                      inputMode="numeric"
                      autoComplete="one-time-code"
                      placeholder="000000"
                      maxLength={6}
                      required
                      value={confirmCode}
                      onChange={(e) => setConfirmCode(e.target.value.trim())}
                      disabled={loading}
                      className="text-center text-lg tracking-widest font-mono bg-background/50"
                    />
                  </div>
                  <Button type="submit" className="w-full rounded-full" disabled={loading || confirmCode.length !== 6}>
                    {loading ? 'Confirming...' : 'Verify'}
                  </Button>
                </form>
              </div>
            )}

            {step === 'backup-codes' && (
              <div className="animate-in fade-in slide-in-from-bottom-2 duration-300">
                <div className="flex items-center gap-4 mb-6">
                  <div className="h-12 w-12 rounded-2xl bg-amber-500/10 flex items-center justify-center text-amber-500">
                    <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" /><line x1="12" y1="8" x2="12" y2="12" /><line x1="12" y1="16" x2="12.01" y2="16" /></svg>
                  </div>
                  <div>
                    <h2 className="text-lg font-semibold text-foreground">Save your backup codes</h2>
                    <p className="text-sm text-muted-foreground">
                      Store these safely. Each code works once.
                    </p>
                  </div>
                </div>
                
                <div className="grid grid-cols-2 gap-3 mb-6 bg-muted/20 p-4 rounded-xl border border-border/50">
                  {backupCodes.map((code) => (
                    <code
                      key={code}
                      className="rounded-lg border border-border/50 bg-background/50 px-3 py-2 text-sm font-mono text-foreground text-center shadow-sm"
                    >
                      {code}
                    </code>
                  ))}
                </div>
                
                <Button className="w-full rounded-full" onClick={() => {
                  setStep('done');
                  setPassword('');
                  setConfirmCode('');
                }}>
                  I've saved my backup codes
                </Button>
              </div>
            )}

            {step === 'done' && (
              <div className="text-center py-8 animate-in zoom-in-95 duration-300">
                <div className="mx-auto mb-6 flex h-20 w-20 items-center justify-center rounded-full bg-emerald-500/10 border border-emerald-500/20 text-emerald-500 shadow-inner">
                  <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><polyline points="20 6 9 17 4 12" /></svg>
                </div>
                <h2 className="text-2xl font-semibold text-foreground mb-2">2FA is enabled</h2>
                <p className="text-sm text-muted-foreground leading-relaxed mb-6">
                  Your account now requires a code from your authenticator app at every login.
                </p>
                <Button variant="destructive" className="w-full rounded-full" onClick={() => { setPassword(''); setStep('disable-prompt'); }}>
                  Disable 2FA
                </Button>
              </div>
            )}

            {step === 'disable-prompt' && (
              <div className="animate-in fade-in slide-in-from-bottom-2 duration-300">
                <div className="flex items-center gap-4 mb-6">
                  <div className="h-12 w-12 rounded-2xl bg-destructive/10 flex items-center justify-center text-destructive">
                    <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" /><line x1="15" y1="9" x2="9" y2="15" /><line x1="9" y1="9" x2="15" y2="15" /></svg>
                  </div>
                  <div>
                    <h2 className="text-lg font-semibold text-foreground">Disable 2FA</h2>
                    <p className="text-sm text-muted-foreground">
                      This will make your account less secure.
                    </p>
                  </div>
                </div>
                
                <form onSubmit={handleDisable} className="space-y-4">
                  <div className="space-y-2">
                    <label htmlFor="disable-password" className="text-sm font-medium text-foreground">
                      Confirm your password to disable
                    </label>
                    <Input
                      id="disable-password"
                      type="password"
                      placeholder="••••••••"
                      required
                      value={password}
                      onChange={(e) => setPassword(e.target.value)}
                      disabled={loading}
                      className="bg-background/50"
                    />
                  </div>
                  <div className="flex gap-3">
                    <Button type="button" variant="outline" className="w-full rounded-full" disabled={loading} onClick={() => setStep('done')}>
                      Cancel
                    </Button>
                    <Button type="submit" variant="destructive" className="w-full rounded-full" disabled={loading}>
                      {loading ? 'Disabling...' : 'Disable 2FA'}
                    </Button>
                  </div>
                </form>
              </div>
            )}

          </CardContent>
        </Card>
      </div>
    </AdminLayout>
  );
};

