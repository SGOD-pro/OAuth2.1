import React, { useState } from 'react';
import { AdminLayout } from './AdminLayout';
import { authClient } from '@/lib/auth-client';
import GlassSurface from '@/components/GlassSurface';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';

type SetupStep = 'idle' | 'qr' | 'backup-codes' | 'done';

/**
 * /admin/security — Enable / manage TOTP 2FA.
 *
 * Flow:
 *   1. Admin enters current password → twoFactor.enable() → returns totpURI + backupCodes
 *   2. Admin scans QR with Google/Microsoft Authenticator
 *   3. Admin enters 6-digit code to confirm → twoFactor.verifyTotp()
 *   4. Backup codes shown once; admin acknowledges
 *
 * No custom TOTP code. All crypto is owned by the Better Auth twoFactor plugin.
 * QR rendered via free qrserver.com API — no npm dependency needed.
 */
export const AdminSecurity: React.FC = () => {
  const [password, setPassword] = useState('');
  const [totpUri, setTotpUri] = useState('');
  const [backupCodes, setBackupCodes] = useState<string[]>([]);
  const [confirmCode, setConfirmCode] = useState('');
  const [step, setStep] = useState<SetupStep>('idle');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  // ── Step 1: enable 2FA ────────────────────────────────────────
  const handleEnable = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError('');

    const { data, error: err } = await authClient.twoFactor.enable({ password });
    if (err || !data) {
      setError(err?.message || 'Failed to start 2FA setup. Check your password.');
      setLoading(false);
      return;
    }

    setTotpUri(data.totpURI);
    setBackupCodes(data.backupCodes);
    setStep('qr');
    setLoading(false);
  };

  // ── Step 2: confirm with TOTP code ────────────────────────────
  const handleConfirm = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError('');

    const { error: err } = await authClient.twoFactor.verifyTotp({ code: confirmCode });
    if (err) {
      setError(err.message || 'Invalid code. Make sure your device clock is accurate.');
      setLoading(false);
      return;
    }

    setStep('backup-codes');
    setLoading(false);
  };

  // ── QR image URL (no npm dep, ponytail: free third-party API) ─
  const qrImageUrl = totpUri
    ? `https://api.qrserver.com/v1/create-qr-code/?size=200x200&data=${encodeURIComponent(totpUri)}`
    : '';

  // ── Manual key (extract secret from URI) ──────────────────────
  const manualKey = totpUri
    ? (new URLSearchParams(totpUri.split('?')[1] ?? '').get('secret') ?? '')
    : '';

  return (
    <AdminLayout>
      <div>
        <p className="text-xs uppercase tracking-[0.18em] text-muted-foreground">Admin</p>
        <h1 className="mt-2 text-2xl font-semibold text-foreground">Security</h1>
        <p className="mt-1 text-sm text-muted-foreground">
          Enable two-factor authentication for your admin account.
        </p>
      </div>

      <div className="mt-6 max-w-lg">
        <GlassSurface
          width="100%"
          height="auto"
          borderRadius={24}
          backgroundOpacity={0.1}
          blur={10}
          saturation={1.6}
        >
          <div className="px-6 py-6">

            {/* ── idle: enter password to begin ── */}
            {step === 'idle' && (
              <>
                <h2 className="text-base font-semibold text-foreground">Enable 2FA</h2>
                <p className="mt-1 text-sm text-muted-foreground">
                  You'll scan a QR code with Google Authenticator or Microsoft Authenticator.
                  Enter your current password to start.
                </p>
                {error && (
                  <div className="mt-4 rounded-2xl border border-destructive/30 bg-destructive/10 px-4 py-3 text-sm text-destructive" role="alert">
                    {error}
                  </div>
                )}
                <form onSubmit={handleEnable} className="mt-5 space-y-4">
                  <div className="space-y-2">
                    <label htmlFor="sec-password" className="text-sm font-medium text-foreground">
                      Current password
                    </label>
                    <Input
                      id="sec-password"
                      type="password"
                      placeholder="••••••••"
                      required
                      value={password}
                      onChange={(e) => setPassword(e.target.value)}
                      disabled={loading}
                    />
                  </div>
                  <Button type="submit" className="w-full" disabled={loading}>
                    {loading ? 'Starting setup…' : 'Set up 2FA'}
                  </Button>
                </form>
              </>
            )}

            {/* ── qr: scan and confirm ── */}
            {step === 'qr' && (
              <>
                <h2 className="text-base font-semibold text-foreground">Scan with your authenticator</h2>
                <p className="mt-1 text-sm text-muted-foreground">
                  Open Google Authenticator or Microsoft Authenticator, tap <strong>+</strong>, and scan this code.
                </p>

                <div className="mt-5 flex justify-center">
                  {/* ponytail: QR via qrserver.com free API; replace with local render if privacy matters */}
                  <img
                    src={qrImageUrl}
                    alt="TOTP QR code"
                    width={200}
                    height={200}
                    className="rounded-xl border border-white/10 bg-white p-2"
                  />
                </div>

                {manualKey && (
                  <div className="mt-4 rounded-2xl border border-white/10 bg-white/5 px-4 py-3">
                    <p className="text-xs uppercase tracking-[0.16em] text-muted-foreground mb-1">Manual entry key</p>
                    <code className="text-sm font-mono text-foreground break-all">{manualKey}</code>
                  </div>
                )}

                {error && (
                  <div className="mt-4 rounded-2xl border border-destructive/30 bg-destructive/10 px-4 py-3 text-sm text-destructive" role="alert">
                    {error}
                  </div>
                )}

                <form onSubmit={handleConfirm} className="mt-5 space-y-4">
                  <div className="space-y-2">
                    <label htmlFor="totp-confirm" className="text-sm font-medium text-foreground">
                      Enter the 6-digit code to confirm
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
                    />
                  </div>
                  <Button type="submit" className="w-full" disabled={loading || confirmCode.length !== 6}>
                    {loading ? 'Confirming…' : 'Confirm and enable'}
                  </Button>
                </form>
              </>
            )}

            {/* ── backup-codes: shown once ── */}
            {step === 'backup-codes' && (
              <>
                <h2 className="text-base font-semibold text-foreground">Save your backup codes</h2>
                <p className="mt-1 text-sm text-muted-foreground">
                  Store these in a safe place. Each code works once. They cannot be shown again.
                </p>
                <div className="mt-5 grid grid-cols-2 gap-2">
                  {backupCodes.map((code) => (
                    <code
                      key={code}
                      className="rounded-xl border border-white/10 bg-white/5 px-3 py-2 text-sm font-mono text-foreground text-center"
                    >
                      {code}
                    </code>
                  ))}
                </div>
                <Button
                  className="mt-6 w-full"
                  onClick={() => setStep('done')}
                >
                  I've saved my backup codes
                </Button>
              </>
            )}

            {/* ── done ── */}
            {step === 'done' && (
              <div className="text-center py-4">
                <div className="mx-auto mb-4 flex h-12 w-12 items-center justify-center rounded-full border border-white/10 bg-white/10">
                  <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                    <polyline points="20 6 9 17 4 12" />
                  </svg>
                </div>
                <h2 className="text-base font-semibold text-foreground">2FA is enabled</h2>
                <p className="mt-1 text-sm text-muted-foreground">
                  Your account now requires a code from your authenticator app at every login.
                </p>
              </div>
            )}

          </div>
        </GlassSurface>
      </div>
    </AdminLayout>
  );
};
