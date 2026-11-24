import React from 'react';
import { Checkbox } from '@/components/ui/checkbox';

interface AmbiguityBannerProps {
  isAmbiguous: boolean;
  reasonCodes: string[];
  reasons: string[];
}

/** Displays canonical ambiguity status and safe reason codes for legacy/misconfigured clients. */
export const ClientAmbiguityBanner: React.FC<AmbiguityBannerProps> = ({ isAmbiguous, reasonCodes, reasons }) => {
  if (!isAmbiguous) return null;
  return (
    <div role="alert" className="rounded-[12px] border border-amber-500/40 bg-amber-500/10 p-3.5 text-xs space-y-1.5">
      <p className="font-semibold text-amber-700 dark:text-amber-300">
        Ambiguous configuration requiring administrative review
      </p>
      {reasonCodes.length > 0 && (
        <div className="flex flex-wrap gap-1">
          {reasonCodes.map((code) => (
            <code key={code} className="rounded bg-amber-500/20 px-1.5 py-0.5 font-mono text-[11px] text-amber-800 dark:text-amber-200">
              {code}
            </code>
          ))}
        </div>
      )}
      {reasons.length > 0 && (
        <ul className="list-disc pl-4 text-amber-700 dark:text-amber-300 space-y-0.5">
          {reasons.map((r) => <li key={r}>{r}</li>)}
        </ul>
      )}
    </div>
  );
};

interface TransitionWarningsProps {
  needsSecretRevokeConfirm: boolean;
  confirmSecretRevoke: boolean;
  onConfirmSecretRevokeChange: (checked: boolean) => void;
  needsPublicToConfidential: boolean;
  needsWideningOpenConfirm: boolean;
  confirmWideningOpen: boolean;
  onConfirmWideningOpenChange: (checked: boolean) => void;
}

/** Renders explicit confirmation prompts for destructive credential or tenant widening transitions. */
export const ClientTransitionWarnings: React.FC<TransitionWarningsProps> = ({
  needsSecretRevokeConfirm,
  confirmSecretRevoke,
  onConfirmSecretRevokeChange,
  needsPublicToConfidential,
  needsWideningOpenConfirm,
  confirmWideningOpen,
  onConfirmWideningOpenChange,
}) => (
  <>
    {needsSecretRevokeConfirm && (
      <div className="rounded-lg border border-destructive/40 bg-destructive/10 p-3.5 text-xs space-y-2">
        <p className="font-medium text-destructive">
          Critical change: Switching from Confidential to Public will revoke and delete the existing client secret. Consumer software must supply PKCE S256 verifiers.
        </p>
        <label className="flex items-center gap-2 cursor-pointer font-medium text-foreground">
          <Checkbox
            data-confirm="revoke-secret"
            checked={confirmSecretRevoke}
            onCheckedChange={(c) => onConfirmSecretRevokeChange(c === true)}
          />
          <span>I understand the existing client secret will be revoked and deleted</span>
        </label>
      </div>
    )}

    {needsPublicToConfidential && (
      <div className="rounded-lg border border-border bg-secondary/40 p-3.5 text-xs text-muted-foreground">
        Switching to Confidential will generate a fresh cryptographically secure client secret upon saving, displayed once.
      </div>
    )}

    {needsWideningOpenConfirm && (
      <div className="rounded-lg border border-amber-500/40 bg-amber-500/10 p-3.5 text-xs space-y-2">
        <p className="font-medium text-amber-700 dark:text-amber-300">
          Tenant membership requirements will no longer be enforced once Open access policy is active.
        </p>
        <label className="flex items-center gap-2 cursor-pointer font-medium text-foreground">
          <Checkbox
            data-confirm="widening-access"
            checked={confirmWideningOpen}
            onCheckedChange={(c) => onConfirmWideningOpenChange(c === true)}
          />
          <span>Confirm widening private application access to Open</span>
        </label>
      </div>
    )}
  </>
);
