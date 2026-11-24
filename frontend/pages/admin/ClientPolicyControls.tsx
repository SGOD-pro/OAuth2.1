import React, { useState } from 'react';
import { Checkbox } from '@/components/ui/checkbox';
import { Button } from '@/components/ui/button';

interface ClientPolicyControlsProps {
  clientType: 'public' | 'confidential';
  accessPolicy: 'open' | 'private';
  isDev: boolean;
  readOnly?: boolean;
  onClientTypeChange: (val: 'public' | 'confidential') => void;
  onAccessPolicyChange: (val: 'open' | 'private') => void;
  onIsDevChange: (val: boolean) => void;
}

export const ClientPolicyControls: React.FC<ClientPolicyControlsProps> = ({
  clientType,
  accessPolicy,
  isDev,
  readOnly = false,
  onClientTypeChange,
  onAccessPolicyChange,
  onIsDevChange,
}) => {
  return (
    <div className="rounded-[12px] border border-border bg-secondary/30 p-4 space-y-4">
      <fieldset disabled={readOnly} className="space-y-2">
        <legend className="font-sans text-xs font-medium text-foreground">
          Client Authentication Type
        </legend>
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5">
          <label
            className={`flex items-start gap-2.5 rounded-lg border p-3 text-xs cursor-pointer transition-colors ${
              clientType === 'confidential' ? 'border-primary bg-primary/5' : 'border-border bg-background/60'
            } ${readOnly ? 'opacity-60 cursor-not-allowed' : ''}`}
          >
            <input
              type="radio"
              name="clientType"
              value="confidential"
              checked={clientType === 'confidential'}
              onChange={() => onClientTypeChange('confidential')}
              disabled={readOnly}
              className="mt-0.5 accent-primary"
            />
            <div>
              <span className="font-medium text-foreground block">Confidential</span>
              <span className="text-muted-foreground">Server application holding a client secret.</span>
            </div>
          </label>
          <label
            className={`flex items-start gap-2.5 rounded-lg border p-3 text-xs cursor-pointer transition-colors ${
              clientType === 'public' ? 'border-primary bg-primary/5' : 'border-border bg-background/60'
            } ${readOnly ? 'opacity-60 cursor-not-allowed' : ''}`}
          >
            <input
              type="radio"
              name="clientType"
              value="public"
              checked={clientType === 'public'}
              onChange={() => onClientTypeChange('public')}
              disabled={readOnly}
              className="mt-0.5 accent-primary"
            />
            <div>
              <span className="font-medium text-foreground block">Public</span>
              <span className="text-muted-foreground">Single page or native app using PKCE S256 without a secret.</span>
            </div>
          </label>
        </div>
      </fieldset>

      <fieldset disabled={readOnly} className="space-y-2">
        <legend className="font-sans text-xs font-medium text-foreground">
          User Access Policy
        </legend>
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5">
          <label
            className={`flex items-start gap-2.5 rounded-lg border p-3 text-xs cursor-pointer transition-colors ${
              accessPolicy === 'private' ? 'border-primary bg-primary/5' : 'border-border bg-background/60'
            } ${readOnly ? 'opacity-60 cursor-not-allowed' : ''}`}
          >
            <input
              type="radio"
              name="accessPolicy"
              value="private"
              checked={accessPolicy === 'private'}
              onChange={() => onAccessPolicyChange('private')}
              disabled={readOnly}
              className="mt-0.5 accent-primary"
            />
            <div>
              <span className="font-medium text-foreground block">Private</span>
              <span className="text-muted-foreground">Restricted to explicitly assigned tenant members.</span>
            </div>
          </label>
          <label
            className={`flex items-start gap-2.5 rounded-lg border p-3 text-xs cursor-pointer transition-colors ${
              accessPolicy === 'open' ? 'border-primary bg-primary/5' : 'border-border bg-background/60'
            } ${readOnly ? 'opacity-60 cursor-not-allowed' : ''}`}
          >
            <input
              type="radio"
              name="accessPolicy"
              value="open"
              checked={accessPolicy === 'open'}
              onChange={() => onAccessPolicyChange('open')}
              disabled={readOnly}
              className="mt-0.5 accent-primary"
            />
            <div>
              <span className="font-medium text-foreground block">Open</span>
              <span className="text-muted-foreground">Accessible to any authenticated platform user.</span>
            </div>
          </label>
        </div>
      </fieldset>

      <div className="pt-1 border-t border-border/60">
        <label className={`flex items-start justify-between gap-4 ${readOnly ? 'opacity-60 cursor-not-allowed' : 'cursor-pointer'}`}>
          <div>
            <div className="flex items-center gap-2">
              <span className="font-sans text-xs font-medium text-foreground">
                Callback Environment: {isDev ? 'Development' : 'Production'}
              </span>
              <span className={`rounded px-1.5 py-0.2 font-sans text-[10px] font-medium border ${
                isDev
                  ? 'bg-amber-500/20 text-amber-600 dark:text-amber-400 border-amber-500/30'
                  : 'bg-secondary text-muted-foreground border-border'
              }`}>
                {isDev ? 'Development' : 'Production'}
              </span>
            </div>
            <span className="font-sans text-xs text-muted-foreground block mt-0.5">
              {isDev
                ? 'Development mode permits local loopback callbacks (localhost, 127.0.0.1, ::1) and requires super admin permission.'
                : 'Production mode requires strict HTTPS callback URLs and rejects loopback URIs.'}
            </span>
          </div>
          <Checkbox
            checked={isDev}
            disabled={readOnly}
            aria-label="Development callbacks mode"
            onCheckedChange={(checked) => onIsDevChange(checked === true)}
          />
        </label>
      </div>
    </div>
  );
};

export const ClientSecretOneTimeCard: React.FC<{
  clientId: string;
  clientSecret?: string;
  onDone: () => void;
}> = ({ clientId, clientSecret, onDone }) => {
  const [copied, setCopied] = useState<'id' | 'secret' | null>(null);
  const [secretCopied, setSecretCopied] = useState(!clientSecret);

  const copy = async (text: string, which: 'id' | 'secret') => {
    try {
      if (navigator.clipboard?.writeText) await navigator.clipboard.writeText(text);
    } catch {
      // Clipboard API may be unavailable outside secure browser contexts.
    }
    setCopied(which);
    if (which === 'secret') setSecretCopied(true);
    setTimeout(() => setCopied(null), 2000);
  };

  return (
    <div className="space-y-4 py-2">
      <div className="rounded-[12px] border border-border bg-secondary/40 p-4">
        <span className="font-sans text-xs font-medium text-muted-foreground block mb-1.5">Client ID</span>
        <div className="flex items-center justify-between gap-3">
          <code className="font-mono text-xs text-foreground break-all">{clientId}</code>
          <Button type="button" size="sm" variant="outline" className="h-8 px-2.5 text-xs shrink-0 rounded-md" onClick={() => void copy(clientId, 'id')}>
            {copied === 'id' ? 'Copied' : 'Copy'}
          </Button>
        </div>
      </div>

      {clientSecret ? (
        <>
          <div className="rounded-[12px] border border-border bg-secondary/40 p-4">
            <span className="font-sans text-xs font-medium text-muted-foreground block mb-1.5">Client Secret</span>
            <div className="flex items-center justify-between gap-3">
              <code className="font-mono text-xs text-foreground break-all">
                {secretCopied ? '••••••••••••••••••••••••••••••••' : clientSecret}
              </code>
              <Button type="button" size="sm" variant="outline" className="h-8 px-2.5 text-xs shrink-0 rounded-md" onClick={() => void copy(clientSecret, 'secret')}>
                {copied === 'secret' ? 'Copied' : 'Copy secret'}
              </Button>
            </div>
          </div>
          <div className="rounded-[12px] border border-amber-500/30 bg-amber-500/10 p-3.5 text-xs text-amber-600 dark:text-amber-300">
            <strong>Security notice:</strong> Client secrets are hashed at rest and cannot be retrieved once you close this dialog.
          </div>
        </>
      ) : (
        <div className="rounded-[12px] border border-border bg-secondary/30 p-3.5 text-xs text-muted-foreground">
          Public client registered without a client secret. Consumer software must use PKCE S256 on authorization code exchange.
        </div>
      )}

      <Button type="button" className="w-full h-9 rounded-md mt-2" disabled={!secretCopied} onClick={onDone}>
        {secretCopied ? 'Done' : 'Copy secret to proceed'}
      </Button>
    </div>
  );
};
