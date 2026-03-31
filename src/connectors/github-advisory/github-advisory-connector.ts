import axios from 'axios';
import { BaseConnector } from '../base/connector';
import { SourceFetchResult } from '../../shared';
import logger from '../../logging';

const GITHUB_ADVISORY_URL = 'https://api.github.com/advisories';
const PER_PAGE = 100;

export interface GitHubAdvisory {
  ghsa_id: string;
  cve_id: string | null;
  url: string;
  html_url: string;
  summary: string;
  description: string;
  severity: 'low' | 'medium' | 'high' | 'critical' | 'unknown';
  author: { login: string } | null;
  publisher: { login: string } | null;
  identifiers: Array<{ type: string; value: string }>;
  state: string;
  published_at: string;
  updated_at: string;
  withdrawn_at: string | null;
  vulnerabilities: Array<{
    package: { ecosystem: string; name: string };
    first_patched_version: string | null;
    vulnerable_version_range: string | null;
    vulnerable_functions: string[];
  }>;
  cvss: {
    vector_string: string | null;
    score: number | null;
  } | null;
  cwes: Array<{ cwe_id: string; name: string }>;
  references: string[];
}

export class GithubAdvisoryConnector extends BaseConnector {
  readonly name = 'github-advisory';
  readonly type = 'github_advisory';

  async fetch(sinceDate?: Date): Promise<SourceFetchResult> {
    try {
      // Default lookback: 30 days on first run
      const effectiveSince = sinceDate ?? new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);
      logger.info({ source: this.name, since: effectiveSince.toISOString() }, 'Fetching GitHub Advisory Database');

      const headers: Record<string, string> = {
        'Accept': 'application/vnd.github+json',
        'X-GitHub-Api-Version': '2022-11-28',
        'User-Agent': 'AdvisoryWire/1.0',
      };

      const token = process.env.GITHUB_TOKEN;
      if (token) {
        headers['Authorization'] = `Bearer ${token}`;
      }

      const params: Record<string, string | number> = {
        type: 'reviewed',
        per_page: PER_PAGE,
        sort: 'published',
        direction: 'desc',
        published: `>${effectiveSince.toISOString().split('T')[0]}`,
      };

      const response = await axios.get<GitHubAdvisory[]>(GITHUB_ADVISORY_URL, {
        params,
        headers,
        timeout: 30000,
      });

      if (!Array.isArray(response.data)) {
        logger.warn({ source: this.name }, 'Unexpected response format from GitHub Advisory API');
        return { success: false, items: [], errorMessage: 'Invalid response format' };
      }

      const items = response.data;
      logger.info({ source: this.name, count: items.length }, 'GitHub Advisory fetch completed');

      return { success: true, items };
    } catch (error) {
      logger.error({ error, source: this.name }, 'GitHub Advisory fetch failed');
      return this.handleError(error);
    }
  }
}
