import axios from 'axios';
import { BaseConnector } from '../base/connector';
import { SourceFetchResult } from '../../shared';
import logger from '../../logging';

// NVD CVE API 2.0 - official NIST endpoint, no IP restrictions
const NVD_API_URL = 'https://services.nvd.nist.gov/rest/json/cves/2.0';
const RESULTS_PER_PAGE = 100;

// Rate limits: 5 req/30s without API key, 50 req/30s with key
const REQUEST_DELAY_MS = 7000; // 7s between calls = safe without API key

interface NvdCveItem {
  id: string;
  sourceIdentifier: string;
  published: string;
  lastModified: string;
  vulnStatus: string;
  descriptions: Array<{ lang: string; value: string }>;
  metrics?: {
    cvssMetricV31?: Array<{
      cvssData: { baseScore: number; baseSeverity: string; vectorString: string };
      exploitabilityScore: number;
      impactScore: number;
    }>;
    cvssMetricV30?: Array<{
      cvssData: { baseScore: number; baseSeverity: string; vectorString: string };
    }>;
    cvssMetricV2?: Array<{
      cvssData: { baseScore: number; vectorString: string };
      baseSeverity: string;
    }>;
  };
  weaknesses?: Array<{ description: Array<{ lang: string; value: string }> }>;
  references?: Array<{ url: string; source: string; tags?: string[] }>;
  cisaExploitAdd?: string;
  cisaActionDue?: string;
  cisaRequiredAction?: string;
  cisaVulnerabilityName?: string;
}

interface NvdApiResponse {
  resultsPerPage: number;
  startIndex: number;
  totalResults: number;
  format: string;
  version: string;
  vulnerabilities: Array<{ cve: NvdCveItem }>;
}

export class NvdConnector extends BaseConnector {
  readonly name = 'nvd';
  readonly type = 'nvd';

  async fetch(sinceDate?: Date): Promise<SourceFetchResult> {
    try {
      // On first run (no sinceDate), use NOW as baseline - fetch nothing, just establish checkpoint.
      // Next poll will fetch only what appeared since this moment.
      const effectiveSince = sinceDate ?? new Date();
      const now = new Date();

      logger.info({ source: this.name, since: effectiveSince.toISOString() }, 'Fetching NVD CVE data');

      const headers: Record<string, string> = {
        'User-Agent': 'AdvisoryWire/1.0',
      };

      const apiKey = process.env.NVD_API_KEY;
      if (apiKey) {
        headers['apiKey'] = apiKey;
      }

      const params: Record<string, string | number> = {
        lastModStartDate: effectiveSince.toISOString().replace('.000Z', '+00:00'),
        lastModEndDate: now.toISOString().replace('.000Z', '+00:00'),
        resultsPerPage: RESULTS_PER_PAGE,
        startIndex: 0,
      };

      // First call to get total
      const firstResp = await axios.get<NvdApiResponse>(NVD_API_URL, { params, headers, timeout: 30000 });
      const total = firstResp.data.totalResults;
      let items: NvdCveItem[] = firstResp.data.vulnerabilities.map(v => v.cve);

      logger.info({ source: this.name, total }, 'NVD total results');

      // Paginate if needed (cap at 500 items = 5 pages to avoid rate limits)
      const maxPages = apiKey ? 10 : 5;
      let page = 1;
      while (items.length < total && page < maxPages) {
        await new Promise(resolve => setTimeout(resolve, apiKey ? 1000 : REQUEST_DELAY_MS));
        const resp = await axios.get<NvdApiResponse>(NVD_API_URL, {
          params: { ...params, startIndex: page * RESULTS_PER_PAGE },
          headers,
          timeout: 30000,
        });
        items.push(...resp.data.vulnerabilities.map(v => v.cve));
        page++;
      }

      logger.info({ source: this.name, fetched: items.length }, 'NVD fetch completed');
      return { success: true, items };
    } catch (error) {
      logger.error({ error, source: this.name }, 'NVD fetch failed');
      return this.handleError(error);
    }
  }
}
