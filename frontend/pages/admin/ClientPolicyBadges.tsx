import React from 'react';
import { Badge } from '@/components/ui/badge';
import type { OAuthClient } from '@/lib/adminStore-types';

export function resolveDisplayPolicy(client: Partial<OAuthClient>) {
  const clientType: 'public' | 'confidential' =
    client.clientType === 'public' || client.clientType === 'confidential'
      ? client.clientType
      : (client.hasClientSecret ? 'confidential' : 'public');
  const accessPolicy: 'open' | 'private' =
    client.accessPolicy === 'open' || client.accessPolicy === 'private'
      ? client.accessPolicy
      : (client.is_public === false || client.isPublic === false ? 'private' : 'open');
  const isDev = Boolean(client.is_dev ?? client.isDev ?? client.metadata?.isDev ?? client.metadata?.is_dev);
  const isAmbiguous = Boolean(client.isAmbiguous || client.classification === 'AMBIGUOUS');
  const isMigrated = client.classification === 'MIGRATED' && !isAmbiguous;
  const isLegacy = Boolean(!isAmbiguous && !isMigrated && client.classification?.startsWith('COMPATIBLE_'));
  return { clientType, accessPolicy, isDev, isAmbiguous, isMigrated, isLegacy };
}

export const ClientPolicyBadges: React.FC<{ client: Partial<OAuthClient>; compact?: boolean }> = ({ client, compact }) => {
  const { clientType, accessPolicy, isDev, isAmbiguous, isMigrated, isLegacy } = resolveDisplayPolicy(client);

  return (
    <div className="flex items-center gap-1.5 flex-wrap">
      <Badge variant="outline" className="text-[11px]">
        {clientType === 'confidential' ? 'Confidential' : 'Public'}
      </Badge>
      <Badge variant={accessPolicy === 'private' ? 'secondary' : 'info'} className="text-[11px]">
        {accessPolicy === 'private' ? 'Private' : 'Open'}
      </Badge>
      <Badge variant={isDev ? 'warning' : 'secondary'} className="text-[11px]">
        {isDev ? 'Development' : 'Production'}
      </Badge>
      {isAmbiguous && (
        <Badge variant="warning" className="text-[11px]">
          Ambiguous
        </Badge>
      )}
      {isMigrated && !compact && (
        <Badge variant="success" className="text-[11px]">
          Migrated
        </Badge>
      )}
      {isLegacy && !compact && (
        <Badge variant="secondary" className="text-[11px]">
          Legacy Compatible
        </Badge>
      )}
    </div>
  );
};
