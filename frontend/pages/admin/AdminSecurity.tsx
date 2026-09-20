import React, { useState, useEffect, useMemo } from 'react';
import { AdminLayout } from './AdminLayout';
import { authClient, useSession } from '@/lib/auth-client';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Card, CardContent } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import { toast } from 'sonner';
import { QRCodeSVG } from 'qrcode.react';
import { usePageTitle } from '@/hooks/usePageTitle';
import { Eye, EyeOff } from 'lucide-react';

type SetupStep = 'idle' | 'qr' | 'done' | 'disable-prompt';

export const AdminSecurity: React.FC = () => {
  usePageTitle('Security');

  const { data: session, refetch, isPending } = useSession();
  const isTwoFactorEnabled = !!(session as unknown as { user?: { twoFactorEnabled?: boolean } })?.user?.twoFactorEnabled;

  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [totpUri, setTotpUri] = useState('');
  const [backupCodes, setBackupCodes] = useState<string[]>([]);
  const [confirmCode, setConfirmCode] = useState('');
  const [step, setStep] = useState<SetupStep>('idle');
  const [loading, setLoading] = useState(false);
  const [showBackupDialog, setShowBackupDialog] = useState(false);
  const [copiedKey, setCopiedKey] = useState(false);
  const [copiedCodes, setCopiedCodes] = useState(false);

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
      toast.error(response.error.message || 'Invalid code. Make sure your device clock is synchronized.');
      setLoading(false);
      return;
    }

    setLoading(false);
    setShowBackupDialog(true);
    await refetch();
  };

  const copyManualKey = async (secret: string) => {
    await navigator.clipboard.writeText(secret);
    setCopiedKey(true);
    toast.success('Secret key copied to clipboard');
    setTimeout(() => setCopiedKey(null as unknown as boolean), 2000);
  };

  const copyBackupCodes = async () => {
    await navigator.clipboard.writeText(backupCodes.join('\n'));
    setCopiedCodes(true);
    toast.success('Backup codes copied to clipboard');
    setTimeout(() => setCopiedCodes(false), 2000);
  };

  const handleCloseBackupDialog = () => {
    setShowBackupDialog(false);
    setStep('done');
    setPassword('');
    setConfirmCode('');
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

  const rawKey = useMemo(() => {
    if (!totpUri) return '';
    return new URLSearchParams(totpUri.split('?')[1] ?? '').get('secret') ?? '';
  }, [totpUri]);

  // Group the secret key into readable 4-character chunks
  const formattedKey = useMemo(() => {
    if (!rawKey) return '';
    return rawKey.match(/.{1,4}/g)?.join(' ') ?? rawKey;
  }, [rawKey]);

  return (
    <AdminLayout>
      <div className="flex flex-col flex-1 max-w-[800px] w-full">
        <div className="mb-6 sm:mb-8">
          <h1 className="font-heading text-2xl sm:text-[34px] font-semibold text-foreground tracking-tight leading-tight">
            Security
          </h1>
          <p className="mt-1 font-sans text-sm text-muted-foreground">
            Manage multi-factor authentication (TOTP) and account recovery settings.
          </p>
        </div>

        <Card className="w-full">
          <CardContent className="p-5 sm:p-7 space-y-6">
            <div className="flex items-center justify-between pb-5 border-b border-border">
              <div>
                <h2 className="font-heading text-base sm:text-lg font-medium text-foreground">
                  Two-factor authentication (TOTP)
                </h2>
                <p className="font-sans text-xs text-muted-foreground mt-0.5">
                  Protect administrative access by requiring a 6-digit code from an authenticator app.
                </p>
              </div>
              <Badge variant={isTwoFactorEnabled ? 'success' : 'secondary'}>
                {isTwoFactorEnabled ? 'Enabled' : 'Disabled'}
              </Badge>
            </div>

            {step === 'done' && (
              <div className="space-y-5">
                <div className="rounded-[12px] border border-emerald-500/30 bg-emerald-500/10 p-4">
                  <div className="flex items-center gap-3">
                    <div className="size-8 rounded-full bg-emerald-500/20 text-emerald-500 flex items-center justify-center shrink-0">
                      <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
                        <polyline points="20 6 9 17 4 12" />
                      </svg>
                    </div>
                    <div>
                      <h3 className="font-sans text-sm font-medium text-foreground">Two-factor authentication is active</h3>
                      <p className="font-sans text-xs text-muted-foreground mt-0.5">Your account requires a TOTP code during each sign-in.</p>
                    </div>
                  </div>
                </div>

                <Button 
                  variant="outline" 
                  className="text-destructive border-destructive/30 hover:bg-destructive/10 h-9 rounded-md text-xs" 
                  onClick={() => setStep('disable-prompt')}
                >
                  Disable two-factor authentication
                </Button>
              </div>
            )}

            {step === 'disable-prompt' && (
              <form onSubmit={handleDisable} className="space-y-4">
                <p className="font-sans text-xs text-destructive">
                  Enter your current account password to confirm disabling two-factor authentication:
                </p>
                <div className="space-y-1.5">
                  <label className="font-sans text-xs font-medium text-foreground">Account Password</label>
                  <div className="relative">
                    <Input 
                      type={showPassword ? "text" : "password"} 
                      placeholder="Enter password" 
                      value={password} 
                      onChange={(e) => setPassword(e.target.value)} 
                      disabled={loading} 
                      required 
                      className="h-9 pr-9"
                    />
                    <button
                      type="button"
                      onClick={() => setShowPassword(!showPassword)}
                      className="absolute right-2.5 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground focus:outline-none"
                      aria-label={showPassword ? "Hide password" : "Show password"}
                      tabIndex={-1}
                    >
                      {showPassword ? <EyeOff className="size-3.5" /> : <Eye className="size-3.5" />}
                    </button>
                  </div>
                </div>
                <div className="flex gap-2.5 pt-1">
                  <Button type="button" variant="outline" onClick={() => setStep('done')} disabled={loading} className="h-9 text-xs">
                    Cancel
                  </Button>
                  <Button type="submit" variant="destructive" disabled={loading} className="h-9 text-xs">
                    {loading ? 'Disabling...' : 'Confirm disable'}
                  </Button>
                </div>
              </form>
            )}

            {step === 'idle' && (
              <form onSubmit={handleEnable} className="space-y-4">
                <p className="font-sans text-sm text-muted-foreground leading-relaxed">
                  Use an authenticator app (such as Google Authenticator, 1Password, or Bitwarden) to generate one-time codes.
                </p>
                <div className="space-y-1.5">
                  <label className="font-sans text-xs font-medium text-foreground">Account Password</label>
                  <div className="relative">
                    <Input 
                      type={showPassword ? "text" : "password"} 
                      placeholder="Enter your password to begin" 
                      value={password} 
                      onChange={(e) => setPassword(e.target.value)} 
                      disabled={loading} 
                      required 
                      className="h-9 pr-9"
                    />
                    <button
                      type="button"
                      onClick={() => setShowPassword(!showPassword)}
                      className="absolute right-2.5 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground focus:outline-none"
                      aria-label={showPassword ? "Hide password" : "Show password"}
                      tabIndex={-1}
                    >
                      {showPassword ? <EyeOff className="size-3.5" /> : <Eye className="size-3.5" />}
                    </button>
                  </div>
                </div>
                <Button type="submit" className="h-9 text-xs mt-1" disabled={loading || !password}>
                  {loading ? 'Preparing setup...' : 'Configure two-factor authentication'}
                </Button>
              </form>
            )}

            {step === 'qr' && (
              <div className="space-y-6">
                <p className="font-sans text-sm text-muted-foreground">
                  Scan this QR code with your authenticator app, or copy the setup key below:
                </p>

                {/* Vertical stacked container for QR and key to prevent flexbox distortion */}
                <div className="flex flex-col items-center gap-5 p-6 rounded-[12px] border border-border bg-secondary/20">
                  <div className="p-3 bg-white rounded-lg shadow-sm">
                    <QRCodeSVG value={totpUri} size={160} />
                  </div>

                  <div className="w-full  space-y-1.5 text-center">
                    <span className="font-sans text-xs text-muted-foreground block">
                      Manual setup key
                    </span>
                    <div className="flex items-center justify-center gap-2 bg-background p-2 rounded-md border border-border">
                      <code className="font-mono text-xs text-foreground tracking-wider select-all break-all">
                        {formattedKey || rawKey}
                      </code>
                      <Button 
                        type="button" 
                        size="sm" 
                        variant="ghost" 
                        className="h-7 px-2 text-xs text-muted-foreground hover:text-foreground shrink-0"
                        onClick={() => copyManualKey(rawKey)}
                      >
                        {copiedKey ? 'Copied' : 'Copy'}
                      </Button>
                    </div>
                  </div>
                </div>

                <form onSubmit={handleConfirm} className="space-y-4">
                  <div className="space-y-1.5">
                    <label className="font-sans text-xs font-medium text-foreground">
                      Verification code
                    </label>
                    <Input 
                      type="text" 
                      placeholder="000000" 
                      maxLength={6} 
                      value={confirmCode} 
                      onChange={(e) => setConfirmCode(e.target.value.trim())} 
                      disabled={loading} 
                      required 
                      className="text-center font-mono text-base tracking-widest h-10"
                    />
                  </div>
                  <div className="flex gap-2.5">
                    <Button type="button" variant="outline" onClick={() => setStep('idle')} disabled={loading} className="h-9 text-xs">
                      Back
                    </Button>
                    <Button type="submit" disabled={loading || confirmCode.length !== 6} className="h-9 text-xs">
                      {loading ? 'Verifying...' : 'Verify and enable'}
                    </Button>
                  </div>
                </form>
              </div>
            )}

          </CardContent>
        </Card>
      </div>

      {/* Backup codes dialog with motorsport accent */}
      <Dialog open={showBackupDialog} onOpenChange={setShowBackupDialog}>
        <DialogContent className="" accent="motorsport">
          <DialogHeader>
            <DialogTitle>Save backup codes</DialogTitle>
            <DialogDescription>
              Store these recovery codes in a secure password manager. Each code can be used once if you lose access to your authenticator app.
            </DialogDescription>
          </DialogHeader>
          <div className="grid grid-cols-2 gap-2 p-4 rounded-[12px] bg-secondary/30 border border-border">
            {backupCodes.map((code, i) => (
              <code key={i} className="font-mono text-xs text-foreground p-1.5 bg-background rounded border border-border text-center select-all">
                {code}
              </code>
            ))}
          </div>
          <DialogFooter className="flex flex-col sm:flex-row sm:justify-between gap-2 mt-2">
            <Button type="button" variant="outline" onClick={copyBackupCodes} className="h-9 text-xs">
              {copiedCodes ? 'Copied!' : 'Copy codes'}
            </Button>
            <Button type="button" onClick={handleCloseBackupDialog} className="h-9 text-xs">
              I have saved my backup codes
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </AdminLayout>
  );
};
