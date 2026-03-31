import axios from 'axios';
import { BaseConnector } from '../base/connector';
import { SourceFetchResult } from '../../shared';
import logger from '../../logging';

// Primary URL - may be blocked by Cloudflare on datacenter IPs
const CISA_KEV_URL = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';
// Fallback: NVD API filtered to CISA KEV vulnerabilities (no IP restrictions)
const NVD_KEV_URL = 'https://services.nvd.nist.gov/rest/json/cves/2.0?hasCertAlerts=true&resultsPerPage=100';

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

      // Try primary CISA URL first, fall back to NVD API if blocked
      let items: CisaKevItem[] = [];
      try {
        const response = await axios.get<CisaKevResponse>(CISA_KEV_URL, {
          timeout: 20000,
          headers: {
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0',
            'Accept': 'application/json, text/plain, */*',
            'Accept-Language': 'en-US,en;q=0.9',
            'Referer': 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog',
            'Cache-Control': 'no-cache',
          },
        });
        if (response.data?.vulnerabilities) {
          items = response.data.vulnerabilities;
          logger.info({ source: this.name, count: items.length }, 'CISA KEV fetched from primary URL');
        }
      } catch (primaryErr: any) {
        logger.warn({ source: this.name, status: primaryErr?.response?.status }, 'Primary CISA KEV URL failed, trying NVD fallback');
        // Fallback: NVD CVE API filtered to CISA KEV (hasCertAlerts)
        const nvdResp = await axios.get<any>(NVD_KEV_URL, {
          timeout: 30000,
          headers: { 'User-Agent': 'AdvisoryWire/1.0' },
        });
        const cves: any[] = nvdResp.data?.vulnerabilities ?? [];
        items = cves.map((entry: any) => {
          const cve = entry.cve;
          return {
            cveID: cve.id,
            vendorProject: cve.sourceIdentifier ?? '',
            product: '',
            vulnerabilityName: cve.descriptions?.find((d: any) => d.lang === 'en')?.value ?? cve.id,
            dateAdded: cve.published?.split('T')[0] ?? new Date().toISOString().split('T')[0],
            shortDescription: cve.descriptions?.find((d: any) => d.lang === 'en')?.value ?? '',
            requiredAction: 'See NVD for details',
            dueDate: '',
            knownRansomwareCampaignUse: 'Unknown',
          } as CisaKevItem;
        });
        logger.info({ source: this.name, count: items.length }, 'CISA KEV fetched from NVD fallback');
      }

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
