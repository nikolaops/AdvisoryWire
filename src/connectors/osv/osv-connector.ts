import axios from 'axios';
import { BaseConnector } from '../base/connector';
import { SourceFetchResult } from '../../shared/types';
import logger from '../../logging';

const OSV_API_URL = 'https://api.osv.dev/v1/query';

interface OsvVulnerability {
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
      logger.info({ source: this.name, sinceDate }, 'Fetching OSV data');

      // For MVP, we'll fetch recent vulnerabilities from npm ecosystem
      // In a real implementation, this would be more sophisticated
      const response = await axios.post<{ vulns: OsvVulnerability[] }>(
        OSV_API_URL,
        {
          package: {
            ecosystem: 'npm',
          },
        },
        {
          timeout: 30000,
          headers: {
            'Content-Type': 'application/json',
            'User-Agent': 'SecurityAdvisoryNotifier/1.0',
          },
        }
      );

      if (!response.data || !response.data.vulns) {
        logger.warn({ source: this.name }, 'No vulnerabilities returned from OSV');
        return {
          success: true,
          items: [],
        };
      }

      let items = response.data.vulns || [];

      // Filter by date if sinceDate provided
      if (sinceDate) {
        items = items.filter(item => {
          if (!item.published) return false;
          const published = new Date(item.published);
          return published > sinceDate;
        });
      }

      // Limit to recent 100 items for MVP
      items = items.slice(0, 100);

      logger.info(
        { source: this.name, totalItems: items.length },
        'OSV fetch completed'
      );

      return {
        success: true,
        items,
      };
    } catch (error) {
      logger.error({ error, source: this.name }, 'OSV fetch failed');
      return this.handleError(error);
    }
  }
}
