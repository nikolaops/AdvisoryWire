import axios from 'axios';
import { BaseConnector } from '../base/connector';
import { SourceFetchResult } from '../../shared';
import { config } from '../../config';
import logger from '../../logging';

// NVD CVE API 2.0 - official NIST endpoint, no IP restrictions
const NVD_API_URL = 'https://services.nvd.nist.gov/rest/json/cves/2.0';
const RESULTS_PER_PAGE = 100;

// Rate limits: 5 req/30s without API key, 50 req/30s with key
const REQUEST_DELAY_MS = 7000; // 7s between calls = safe without API key

interface NvdCpeMatch {
  vulnerable: boolean;
  criteria: string;
  matchCriteriaId?: string;
}

interface NvdConfigNode {
  operator: string;
  negate: boolean;
  cpeMatch: NvdCpeMatch[];
}

interface NvdConfiguration {
  nodes: NvdConfigNode[];
}

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
  configurations?: NvdConfiguration[];
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

  /**
   * Returns true if the CVE matches any of the configured ecosystems.
   * Checks CPE `criteria` strings first (most precise), then falls back to
   * the English description (catches advisories without CPE data yet).
   *
   * CPE criteria format: cpe:2.3:a:<vendor>:<product>:…
   * Ecosystem keyword examples:
   *   npm       → criteria contains "npmjs"  OR description contains "npm"
   *   nuget     → criteria contains "nuget"
   *   pypi      → criteria contains "python" OR description contains "pypi"
   *   maven     → criteria contains "maven"  OR description contains "maven"
   *   rubygems  → criteria contains "rubygems"
   *   golang    → criteria contains "golang" OR description contains "golang"
   *   packagist → criteria contains "packagist"
   *   cargo     → criteria contains "cargo"  OR description contains "cargo"
   */
  private matchesEcosystems(item: NvdCveItem, ecosystems: string[]): boolean {
    // Check CPE configurations (most reliable signal)
    for (const conf of item.configurations ?? []) {
      for (const node of conf.nodes ?? []) {
        for (const match of node.cpeMatch ?? []) {
          const criteria = match.criteria?.toLowerCase() ?? '';
          if (ecosystems.some(eco => criteria.includes(eco))) return true;
        }
      }
    }

    // Fallback: English description (catches in-progress CVEs with no CPE yet)
    const desc = (item.descriptions.find(d => d.lang === 'en')?.value ?? '').toLowerCase();
    if (ecosystems.some(eco => desc.includes(eco))) return true;

    return false;
  }

  async fetch(sinceDate?: Date): Promise<SourceFetchResult> {
    try {
      // Never look back more than 1h regardless of downtime or sinceDate
      const maxLookback = new Date(Date.now() - 60 * 60 * 1000);
      const effectiveSince = sinceDate
        ? (sinceDate > maxLookback ? sinceDate : maxLookback)
        : new Date();
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

      // Apply ecosystem filter if configured
      const ecosystems = config.nvd.ecosystems;
      if (ecosystems.length > 0) {
        const before = items.length;
        items = items.filter(item => this.matchesEcosystems(item, ecosystems));
        logger.info(
          { source: this.name, before, after: items.length, ecosystems },
          'NVD ecosystem filter applied'
        );
      }

      return { success: true, items };
    } catch (error) {
      logger.error({ error, source: this.name }, 'NVD fetch failed');
      return this.handleError(error);
    }
  }
}
