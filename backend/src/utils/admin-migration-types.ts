export interface MigrateLegacyAppAdminsOptions {
  dryRun?: boolean;
}

export interface MigrationConflict {
  adminDocId: string;
  clientId: string;
  email: string;
  reason: string;
}

export interface MigratedRecord {
  adminDocId: string;
  clientId: string;
  email: string;
  userId: string;
  status: string;
}

export interface MigrationResult {
  migratedCount: number;
  conflictCount: number;
  skippedCount: number;
  conflicts: MigrationConflict[];
  migrated: MigratedRecord[];
}
