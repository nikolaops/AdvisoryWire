import axios from 'axios';
import { BaseConnector } from '../base/connector';
import { SourceFetchResult } from '../../shared';
import logger from '../../logging';

const CISA_KEV_URL = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';

interface CisaKevItem {
  cveID: string;
  vendorProject: string;
  product: string;
  vulnerabilityName: string;
  dateAdded: string;
  shortDescription: string;
  requiredAction: string;
  dueDate: string;
  knownRansomwareCampaignUse: string;
  notes?: string;
}

interface CisaKevResponse {
  title: string;
  catalogVersion: string;
  dateReleased: string;
  count: number;
  vulnerabilities: CisaKevItem[];
}

export class CisaKevConnector extends BaseConnector {
  readonly name = 'cisa-kev';
  readonly type = 'cisa_kev';

  async fetch(sinceDate?: Date): Promise<SourceFetchResult> {
    try {
      logger.info({ source: this.name, sinceDate }, 'Fetching CISA KEV data');

      const response = await axios.get<CisaKevResponse>(CISA_KEV_URL, {
        timeout: 30000,
        headers: {
          'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0',
          'Accept': 'application/json, text/plain, */*',
          'Accept-Language': 'en-US,en;q=0.9',
          'Accept-Encoding': 'gzip, deflate, br',
          'Cache-Control': 'no-cache',
        },
      });

      if (!response.data || !response.data.vulnerabilities) {
        logger.warn({ source: this.name }, 'Invalid response format from CISA KEV');
        return {
          success: false,
          items: [],
          errorMessage: 'Invalid response format',
        };
      }

      let items = response.data.vulnerabilities;

      // Filter by date if sinceDate provided
      if (sinceDate) {
        items = items.filter(item => {
          const dateAdded = new Date(item.dateAdded);
          return dateAdded > sinceDate;
        });
      }

      logger.info(
        { source: this.name, totalItems: items.length, filteredItems: items.length },
        'CISA KEV fetch completed'
      );

      return {
        success: true,
        items,
      };
    } catch (error) {
      logger.error({ error, source: this.name }, 'CISA KEV fetch failed');
      return this.handleError(error);
    }
  }
}
