import React, { useState, useEffect } from 'react';
import { AdminLayout } from './AdminLayout';
import { authClient, useSession } from '@/lib/auth-client';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Card, CardContent } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
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

  useEffect(() => {
    if (isPending) return;
    if (isTwoFactorEnabled) {
      setStep('done');
    } else {
      setStep('idle');
    }
  }, [isTwoFactorEnabled, isPending]);

  const handleEnable = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);

    const { data, error: err } = await authClient.twoFactor.enable({ password });
    if (err || !data) {
      toast.error(err?.message || 'Failed to start 2FA setup. Check your password.');
      setLoading(false);
      return;
    }

    if ('totpURI' in data) {
      setTotpUri(data.totpURI);
      setBackupCodes(data.backupCodes || []);
      setStep('qr');
    }
    setLoading(false);
  };

  const handleConfirm = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);

    const response = await authClient.twoFactor.verifyTotp({ code: confirmCode });
    if (response.error) {
      toast.error(response.error.message || 'Invalid code. Make sure your device clock is accurate.');
      setLoading(false);
      return;
    }

    setStep('backup-codes');
    setLoading(false);
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

  return (
    <AdminLayout>
      <div className="flex flex-col flex-1 max-w-[900px] w-full">
        <div className="mb-8">
          <span className="font-mono text-xs uppercase tracking-[0.2em] text-accent mb-1 block">
            Cryptographic Authentication
          </span>
          <h1 className="font-heading text-3xl sm:text-[42px] leading-[1.1] font-normal text-foreground">
            Security & MFA Telemetry
          </h1>
          <p className="mt-2 font-sans text-sm text-muted-foreground">
            Manage multi-factor TOTP authentication, cryptographic keys, and emergency backup codes.
          </p>
        </div>

        <Card className="w-full">
          <CardContent className="p-8 sm:p-[34px] space-y-6">
            <div className="flex items-center justify-between pb-6 border-b border-border/50">
              <div>
                <h2 className="font-heading text-xl font-medium text-foreground">Two-Factor Authentication (TOTP)</h2>
                <p className="font-sans text-xs text-muted-foreground mt-1">
                  Enforce hardware-bound or app-based 6-digit TOTP validation on administrative sign-ins.
                </p>
              </div>
              <Badge variant={isTwoFactorEnabled ? 'success' : 'outline'}>
                {isTwoFactorEnabled ? 'ENFORCED' : 'INACTIVE'}
              </Badge>
            </div>

            {step === 'done' && (
              <div className="space-y-6 animate-in fade-in duration-300">
                <div className="rounded-[16px] border border-emerald-500/30 bg-emerald-500/5 p-5">
                  <div className="flex items-center gap-3">
                    <div className="size-8 rounded-full bg-emerald-500/10 text-emerald-500 flex items-center justify-center">
                      <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                        <polyline points="20 6 9 17 4 12" />
                      </svg>
                    </div>
                    <div>
                      <h4 className="font-sans text-sm font-medium text-foreground">MFA Telemetry Active</h4>
                      <p className="font-sans text-xs text-muted-foreground">Your administrative profile requires TOTP validation at every session initialization.</p>
                    </div>
                  </div>
                </div>

                <Button 
                  variant="outline" 
                  className="text-destructive border-destructive/30 hover:bg-destructive/10" 
                  onClick={() => setStep('disable-prompt')}
                >
                  Disable Two-Factor Auth
                </Button>
              </div>
            )}

            {step === 'disable-prompt' && (
              <form onSubmit={handleDisable} className="space-y-4 animate-in fade-in duration-300">
                <p className="font-sans text-sm text-destructive leading-relaxed">
                  Enter your current administrator password to confirm disabling two-factor protection:
                </p>
                <div className="space-y-1">
                  <label className="font-mono text-xs uppercase tracking-wider text-muted-foreground">Admin Password</label>
                  <Input 
                    type="password" 
                    placeholder="••••••••••••" 
                    value={password} 
                    onChange={(e) => setPassword(e.target.value)} 
                    disabled={loading} 
                    required 
                  />
                </div>
                <div className="flex gap-3 pt-2">
                  <Button type="button" variant="outline" onClick={() => setStep('done')} disabled={loading}>
                    Cancel
                  </Button>
                  <Button type="submit" variant="destructive" disabled={loading}>
                    {loading ? 'Disabling...' : 'Confirm Disable'}
                  </Button>
                </div>
              </form>
            )}

            {step === 'idle' && (
              <form onSubmit={handleEnable} className="space-y-4 animate-in fade-in duration-300">
                <p className="font-sans text-sm text-muted-foreground leading-relaxed">
                  Enhance console defense by linking an authenticator app (Google Authenticator, 1Password, Bitwarden).
                </p>
                <div className="space-y-1">
                  <label className="font-mono text-xs uppercase tracking-wider text-muted-foreground">Confirm Admin Password</label>
                  <Input 
                    type="password" 
                    placeholder="••••••••••••" 
                    value={password} 
                    onChange={(e) => setPassword(e.target.value)} 
                    disabled={loading} 
                    required 
                  />
                </div>
                <Button type="submit" className="mt-2" disabled={loading || !password}>
                  {loading ? 'Initializing Setup...' : 'Begin MFA Setup'}
                </Button>
              </form>
            )}

            {step === 'qr' && (
              <div className="space-y-6 animate-in fade-in duration-300">
                <p className="font-sans text-sm text-muted-foreground">
                  Scan this QR code with your authenticator device, or manually import the secret key:
                </p>

                <div className="flex flex-col sm:flex-row items-center gap-6 p-6 rounded-[16px] border border-border/60 bg-secondary/30">
                  <div className="p-3 bg-white rounded-xl shadow-sm">
                    <QRCodeSVG value={totpUri} size={150} />
                  </div>
                  <div className="flex-1 min-w-0 space-y-2 text-center sm:text-left">
                    <span className="font-mono text-xs uppercase tracking-wider text-muted-foreground block">
                      Manual Secret Key:
                    </span>
                    <code className="font-mono text-xs bg-background p-2.5 rounded-md border border-border block break-all text-foreground select-all">
                      {manualKey}
                    </code>
                  </div>
                </div>

                <form onSubmit={handleConfirm} className="space-y-4">
                  <div className="space-y-1">
                    <label className="font-mono text-xs uppercase tracking-wider text-muted-foreground">
                      6-Digit Authenticator Code
                    </label>
                    <Input 
                      type="text" 
                      placeholder="000000" 
                      maxLength={6} 
                      value={confirmCode} 
                      onChange={(e) => setConfirmCode(e.target.value.trim())} 
                      disabled={loading} 
                      required 
                      className="text-center font-mono text-lg tracking-widest"
                    />
                  </div>
                  <div className="flex gap-3">
                    <Button type="button" variant="outline" onClick={() => setStep('idle')} disabled={loading}>
                      Back
                    </Button>
                    <Button type="submit" disabled={loading || confirmCode.length !== 6}>
                      {loading ? 'Verifying...' : 'Verify & Enable'}
                    </Button>
                  </div>
                </form>
              </div>
            )}

            {step === 'backup-codes' && (
              <div className="space-y-6 animate-in fade-in duration-300">
                <div className="rounded-[16px] border border-accent/30 bg-accent/5 p-5">
                  <h4 className="font-sans text-sm font-medium text-foreground">Save Emergency Backup Codes</h4>
                  <p className="font-sans text-xs text-muted-foreground mt-1">
                    Store these emergency keys in a secure offline vault. Each key can be used once if you lose device access.
                  </p>
                </div>

                <div className="grid grid-cols-2 gap-2.5 p-5 rounded-[16px] bg-secondary/40 border border-border">
                  {backupCodes.map((code, i) => (
                    <code key={i} className="font-mono text-xs text-foreground p-1.5 bg-background/80 rounded border border-border/40 text-center select-all">
                      {code}
                    </code>
                  ))}
                </div>

                <Button onClick={() => setStep('done')} className="w-full">
                  I Have Secured My Backup Codes
                </Button>
              </div>
            )}
          </CardContent>
        </Card>
      </div>
    </AdminLayout>
  );
};
