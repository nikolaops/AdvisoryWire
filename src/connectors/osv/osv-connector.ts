import axios from 'axios';
import { BaseConnector } from '../base/connector';
import { SourceFetchResult } from '../../shared';
import logger from '../../logging';

// OSV GCS bucket - lists all vulnerabilities per ecosystem
const OSV_GCS_LIST_URL = 'https://storage.googleapis.com/storage/v1/b/osv-vulnerabilities/o';
const OSV_GCS_DOWNLOAD_BASE = 'https://storage.googleapis.com/osv-vulnerabilities';

// Ecosystems to monitor (exact names from osv.dev/list)
const ECOSYSTEMS = [
  'npm',            // Node.js packages (216,497)
  'PyPI',           // Python packages (18,308)
  'Go',             // Go modules (6,293)
  'NuGet',          // .NET packages (1,619)
  'Pub',            // Dart/Flutter packages (10)
  'Ubuntu',         // Ubuntu Linux advisories (51,672)
  'Linux',          // Linux kernel (15,364)
  'GIT',            // Git (79,668)
  'GitHub Actions', // GitHub Actions (47)
  'VSCode',         // VS Code extensions (18)
];
// Max items to fetch per ecosystem per run
const MAX_PER_ECOSYSTEM = 20;

interface GcsObject {
  name: string;
  updated: string;
  size: string;
}

interface GcsListResponse {
  items?: GcsObject[];
  nextPageToken?: string;
}

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
    try {
      logger.info({ source: this.name, ecosystems: ECOSYSTEMS }, 'Fetching OSV data from GCS');

      const allVulns: OsvVulnerability[] = [];

      for (const ecosystem of ECOSYSTEMS) {
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
    // Default lookback: 3 days on first run
    const effectiveSince = sinceDate ?? new Date(Date.now() - 3 * 24 * 60 * 60 * 1000);

    // List recent objects in GCS bucket for this ecosystem
    const listResponse = await axios.get<GcsListResponse>(OSV_GCS_LIST_URL, {
      params: {
        prefix: `${ecosystem}/`,
        maxResults: 200,
        fields: 'items(name,updated)',
      },
      timeout: 30000,
    });

    if (!listResponse.data.items || listResponse.data.items.length === 0) {
      return [];
    }

    // Sort by updated descending and take most recent
    let objects = listResponse.data.items
      .filter(obj => obj.name.endsWith('.json'))
      .sort((a, b) => new Date(b.updated).getTime() - new Date(a.updated).getTime());

    // Filter by effective since date (always set - either sinceDate or 30-day default)
    objects = objects.filter(obj => new Date(obj.updated) > effectiveSince);

    objects = objects.slice(0, MAX_PER_ECOSYSTEM);

    // Fetch each vulnerability JSON - GCS updated filter already handles recency
    const vulns: OsvVulnerability[] = [];
    for (const obj of objects) {
      try {
        const url = `${OSV_GCS_DOWNLOAD_BASE}/${obj.name}`;
        const res = await axios.get<OsvVulnerability>(url, { timeout: 15000 });
        if (res.data && res.data.id) {
          vulns.push(res.data);
        }
      } catch {
        // Skip individual failures
      }
    }
          vulns.push(res.data);
        }
      } catch {
        // Skip individual failures
      }
    }

    return vulns;
  }
}
