export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'unknown';
export type ExploitStatus = 'exploited' | 'not_exploited' | 'unknown';
export type AdvisoryStatus = 'active' | 'withdrawn' | 'unknown';
export type RoutingClass = 'instant_alert' | 'digest' | 'ignore';

export interface NormalizedAdvisory {
  externalId: string;
  source: string;
  title: string;
  summary: string;
  severity: Severity;
  publishedAt: Date;
  updatedAt: Date | null;
  vendor: string | null;
  cveIds: string[];
  references: AdvisoryReference[];
  tags: string[];
  exploitStatus: ExploitStatus;
  status: AdvisoryStatus;
  rawPayload: any;
  rawHash: string;
}

export interface AdvisoryReference {
  url: string;
  label: string | null;
}

export interface StoredAdvisory extends NormalizedAdvisory {
  id: number;
  sourceId: number;
  createdAt: Date;
  modifiedAt: Date;
}

export interface SourceFetchResult {
  success: boolean;
  items: any[];
  errorMessage?: string;
}

export interface DeduplicationResult {
  isNew: boolean;
  existingAdvisoryId?: number;
  isDifferent?: boolean;
}

export interface ScoringResult {
  score: number;
  routingClass: RoutingClass;
  reason: string;
}
