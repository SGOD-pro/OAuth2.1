/**
 * OAuth V2 Client Policy Dimension and Audit Types (Slice P1a)
 */

export type ClientType = "public" | "confidential";
export type AccessPolicy = "open" | "private";

export type ClientClassification =
  | "MIGRATED"
  | "COMPATIBLE_OPEN_PUBLIC"
  | "COMPATIBLE_PRIVATE_CONFIDENTIAL"
  | "COMPATIBLE_OPEN_CONFIDENTIAL"
  | "COMPATIBLE_PRIVATE_PUBLIC"
  | "AMBIGUOUS";

export type AmbiguityReasonCode =
  | "MISSING_REDIRECT_URIS"
  | "INVALID_REDIRECT_URI"
  | "CONFLICTING_ACCESS_FLAGS"
  | "CONFLICTING_DEV_FLAGS"
  | "CONFLICTING_ID_FIELDS"
  | "CONFLICTING_METADATA"
  | "UNCERTAIN_AUTHENTICATION_TYPE"
  | "PARTIAL_EXPLICIT_POLICY"
  | "MISSING_ACCESS_METADATA"
  | "MALFORMED_ACCESS_METADATA"
  | "MALFORMED_DEV_FLAGS"
  | "CONFLICTING_AUTH_METHOD";

export interface ResolvedClientPolicy {
  clientType: ClientType;
  accessPolicy: AccessPolicy;
  isDev: boolean;
  classification: ClientClassification;
  isExplicit: boolean;
  isAmbiguous: boolean;
  reasonCodes: AmbiguityReasonCode[];
  reasons: string[];
}

export interface ClientAuditRecord {
  id: string;
  clientId: string;
  name: string;
  classification: ClientClassification;
  resolvedClientType?: ClientType;
  resolvedAccessPolicy?: AccessPolicy;
  isDev: boolean;
  isAmbiguous: boolean;
  reasonCodes: AmbiguityReasonCode[];
  reasons: string[];
}

export interface ClientAuditSummary {
  totalClients: number;
  migratedCount: number;
  compatibleOpenPublicCount: number;
  compatiblePrivateConfidentialCount: number;
  compatibleOpenConfidentialCount: number;
  compatiblePrivatePublicCount: number;
  ambiguousCount: number;
  clients: ClientAuditRecord[];
  timestamp: string;
}
