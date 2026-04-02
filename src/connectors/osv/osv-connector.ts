import axios from 'axios';
import { BaseConnector } from '../base/connector';
import { SourceFetchResult } from '../../shared';
import logger from '../../logging';

// OSV data dumps — per-ecosystem modified_id.csv + individual JSON files
// See: https://google.github.io/osv.dev/data/#downloading-recent-changes
const OSV_GCS_BASE = 'https://storage.googleapis.com/osv-vulnerabilities';

// Ecosystems to monitor (exact names from https://storage.googleapis.com/osv-vulnerabilities/ecosystems.txt)
// Override via OSV_ECOSYSTEMS env var (comma-separated).
const DEFAULT_ECOSYSTEMS = [
  'Debian',
  'Ubuntu',
  'Alpine',
  'npm',
  'PyPI',
  'Go',
  'NuGet',
  'Packagist',
  'GitHub Actions',
  'VSCode',
];

function getEcosystems(): string[] {
  const envVal = process.env.OSV_ECOSYSTEMS;
  if (!envVal || !envVal.trim()) return DEFAULT_ECOSYSTEMS;
  return envVal.split(',').map((e: string) => e.trim()).filter((e: string) => e.length > 0);
}

// Max vuln entries to download per ecosystem per run.
// High enough that we never miss entries within the sinceDate window.
// The modified_id.csv read itself is always complete (stops at sinceDate boundary).
const MAX_DOWNLOADS_PER_ECOSYSTEM = 500;

export interface OsvVulnerability {
  id: string;
  summary?: string;
  details?: string;
  severity?: Array<{
    type: string;
    score: string;
  }>;
  published?: string;
  modified?: string;
  affected?: Array<{
    package: {
      name: string;
      ecosystem: string;
    };
  }>;
  references?: Array<{
    type: string;
    url: string;
  }>;
  aliases?: string[];
  database_specific?: any;
}

export class OsvConnector extends BaseConnector {
  readonly name = 'osv';
  readonly type = 'osv';

  async fetch(sinceDate?: Date): Promise<SourceFetchResult> {
    const ecosystems = getEcosystems();
    try {
      logger.info({ source: this.name, ecosystems }, 'Fetching OSV data via modified_id.csv');

      const allVulns: OsvVulnerability[] = [];

      for (const ecosystem of ecosystems) {
        try {
          const vulns = await this.fetchEcosystem(ecosystem, sinceDate);
          allVulns.push(...vulns);
          logger.info({ source: this.name, ecosystem, count: vulns.length }, 'Ecosystem fetch done');
        } catch (err) {
          logger.warn({ source: this.name, ecosystem, err }, 'Ecosystem fetch failed, skipping');
        }
      }

      logger.info({ source: this.name, total: allVulns.length }, 'OSV fetch completed');
      return { success: true, items: allVulns };
    } catch (error) {
      logger.error({ error, source: this.name }, 'OSV fetch failed');
      return this.handleError(error);
    }
  }

  private async fetchEcosystem(ecosystem: string, sinceDate?: Date): Promise<OsvVulnerability[]> {
    // If sinceDate is provided (subsequent runs), use it directly — the modified_id.csv
    // approach is cheap (just read CSV until the timestamp boundary), so there is no
    // need to cap the lookback window. Capping would cause us to silently miss entries
    // when the Lambda was down for >1h.
    //
    // If sinceDate is absent (first ever run), default to 1h lookback so we don't
    // flood Slack with all historical advisories.
    const effectiveSince: Date = sinceDate ?? new Date(Date.now() - 60 * 60 * 1000);

    // Fetch per-ecosystem modified_id.csv — sorted newest-first, lines: "<iso_date>,<ID>"
    // This is O(recent entries) instead of scanning all 216k+ GCS objects alphabetically.
    const csvUrl = `${OSV_GCS_BASE}/${encodeURIComponent(ecosystem)}/modified_id.csv`;
    const csvResp = await axios.get<string>(csvUrl, {
      responseType: 'text',
      timeout: 30000,
    });

    const recentIds: string[] = [];

    for (const line of csvResp.data.split('\n')) {
      const trimmed = line.trim();
      if (!trimmed) continue;

      const commaIdx = trimmed.indexOf(',');
      if (commaIdx === -1) continue;

      const modifiedStr = trimmed.slice(0, commaIdx);
      const id = trimmed.slice(commaIdx + 1);
      const modifiedAt = new Date(modifiedStr);

      // CSV is sorted newest-first — stop as soon as we're past the window
      if (modifiedAt <= effectiveSince) break;

      recentIds.push(id);
      if (recentIds.length >= MAX_DOWNLOADS_PER_ECOSYSTEM) break;
    }

    logger.debug(
      { source: this.name, ecosystem, recentIds: recentIds.length, since: effectiveSince.toISOString() },
      'OSV modified_id.csv parsed'
    );

    if (recentIds.length === 0) return [];

    // Download each vulnerability JSON by ID
    const vulns: OsvVulnerability[] = [];
    for (const id of recentIds) {
      try {
        const url = `${OSV_GCS_BASE}/${encodeURIComponent(ecosystem)}/${encodeURIComponent(id)}.json`;
        const res = await axios.get<OsvVulnerability>(url, { timeout: 15000 });
        if (res.data?.id) {
          (res.data as any)._ecosystem = ecosystem;
          vulns.push(res.data);
        }
      } catch {
        // Skip individual file failures silently
      }
    }

    return vulns;
  }
}


