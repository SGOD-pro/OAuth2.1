import React from 'react';
import { Button } from '@/components/ui/button';
import { LogOut, Plus, UserCheck } from 'lucide-react';

export interface BrowserAccountEntry {
  entryId: string;
  status: 'active' | 'signed_out';
  label: string;
  addedAt?: string;
  lastUsedAt?: string;
}

interface AccountChooserProps {
  accounts: BrowserAccountEntry[];
  selectingEntryId: string | null;
  signingOutEntryId: string | null;
  error: string | null;
  onSelectAccount: (entryId: string) => void;
  onSignOutAccount: (entryId: string) => void;
  onSignInAgain: () => void;
  onUseAnotherAccount: () => void;
}

export const AccountChooser: React.FC<AccountChooserProps> = ({
  accounts,
  selectingEntryId,
  signingOutEntryId,
  error,
  onSelectAccount,
  onSignOutAccount,
  onSignInAgain,
  onUseAnotherAccount,
}) => {
  return (
    <div className="space-y-4">
      <div>
        <h2 className="font-heading text-xl font-semibold text-foreground">
          Choose an account
        </h2>
        <p className="font-sans text-xs text-muted-foreground mt-1">
          Select an account in this browser to continue, or add another account.
        </p>
      </div>

      {error && (
        <div role="alert" className="rounded-lg border border-destructive/30 bg-destructive/10 px-3.5 py-2.5 text-xs text-destructive">
          {error}
        </div>
      )}

      <div data-testid="chooser-list" className="space-y-2">
        {accounts.map((acc) =>
          acc.status === 'active' ? (
            <div key={acc.entryId} className="flex items-center gap-2 rounded-lg border border-border bg-secondary/30 p-2">
              <button
                type="button"
                data-testid={`choose-account-${acc.label}`}
                disabled={Boolean(selectingEntryId || signingOutEntryId)}
                onClick={() => onSelectAccount(acc.entryId)}
                className="flex-1 flex items-center justify-between text-left px-2.5 py-2 rounded-md hover:bg-secondary/70 transition-colors disabled:opacity-50"
              >
                <span className="flex items-center gap-2.5 min-w-0">
                  <UserCheck className="size-4 text-primary shrink-0" />
                  <span className="font-sans text-sm font-medium text-foreground truncate">{acc.label}</span>
                </span>
                <span className="font-mono text-[11px] text-emerald-700 dark:text-emerald-300 bg-emerald-500/10 px-2 py-0.5 rounded-pill shrink-0">
                  {selectingEntryId === acc.entryId ? 'Continuing...' : 'Signed in'}
                </span>
              </button>
              <Button
                type="button"
                variant="ghost"
                size="sm"
                data-testid={`signout-account-${acc.label}`}
                disabled={Boolean(selectingEntryId || signingOutEntryId)}
                onClick={() => onSignOutAccount(acc.entryId)}
                title={`Sign out ${acc.label}`}
                className="shrink-0 text-xs text-muted-foreground hover:text-destructive"
              >
                <LogOut className="size-3.5 mr-1" />
                {signingOutEntryId === acc.entryId ? '...' : 'Sign out'}
              </Button>
            </div>
          ) : (
            <div
              key={acc.entryId}
              data-testid={`signedout-account-${acc.label}`}
              className="flex items-center justify-between gap-2 rounded-lg border border-border/70 bg-secondary/10 px-3.5 py-2.5"
            >
              <div className="min-w-0">
                <p className="font-sans text-sm font-medium text-muted-foreground truncate">{acc.label}</p>
                <p className="font-mono text-[11px] text-muted-foreground">Signed out</p>
              </div>
              <Button type="button" variant="outline" size="sm" onClick={onSignInAgain}>
                Sign in again
              </Button>
            </div>
          )
        )}
      </div>

      <Button type="button" variant="outline" className="w-full h-10" onClick={onUseAnotherAccount}>
        <Plus className="size-4 mr-2" />
        Use another account
      </Button>
    </div>
  );
};
