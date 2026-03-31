import { NormalizedAdvisory, Severity, ExploitStatus, AdvisoryStatus } from '../../shared/types';
import { generateHash, normalizeDate, normalizeSeverity } from '../../shared/utils';

export interface Normalizer {
  normalize(rawItem: any): NormalizedAdvisory;
}

export class CisaKevNormalizer implements Normalizer {
  normalize(rawItem: any): NormalizedAdvisory {
    const cveId = rawItem.cveID || 'UNKNOWN';
    
    return {
      externalId: cveId,
      source: 'cisa-kev',
      title: rawItem.vulnerabilityName || `${rawItem.vendorProject} ${rawItem.product} vulnerability`,
      summary: rawItem.shortDescription || '',
      severity: 'high', // CISA KEV items are considered high severity by default
      publishedAt: normalizeDate(rawItem.dateAdded) || new Date(),
      updatedAt: null,
      vendor: rawItem.vendorProject || null,
      cveIds: [cveId],
      references: [
        {
          url: `https://nvd.nist.gov/vuln/detail/${cveId}`,
          label: 'NVD',
        },
      ],
      tags: rawItem.knownRansomwareCampaignUse === 'Known' ? ['ransomware'] : [],
      exploitStatus: 'exploited' as ExploitStatus, // All KEV items are exploited
      status: 'active' as AdvisoryStatus,
      rawPayload: rawItem,
      rawHash: generateHash(rawItem),
    };
  }
}

export class OsvNormalizer implements Normalizer {
  normalize(rawItem: any): NormalizedAdvisory {
    const osvId = rawItem.id || 'UNKNOWN';
    const cveIds = (rawItem.aliases || []).filter((alias: string) => alias.startsWith('CVE-'));
    
    // Determine severity from CVSS if available
    let severity: Severity = 'unknown';
    if (rawItem.severity && rawItem.severity.length > 0) {
      const cvss = rawItem.severity.find((s: any) => s.type === 'CVSS_V3');
      if (cvss) {
        const score = parseFloat(cvss.score.split(':')[1] || '0');
        if (score >= 9.0) severity = 'critical';
        else if (score >= 7.0) severity = 'high';
        else if (score >= 4.0) severity = 'medium';
        else severity = 'low';
      }
    }

    // Extract vendor from affected packages
    let vendor: string | null = null;
    if (rawItem.affected && rawItem.affected.length > 0) {
      vendor = rawItem.affected[0].package?.ecosystem || null;
    }

    // Build references
    const references = (rawItem.references || []).map((ref: any) => ({
      url: ref.url,
      label: ref.type || null,
    }));

    return {
      externalId: osvId,
      source: 'osv',
      title: rawItem.summary || `Vulnerability ${osvId}`,
      summary: rawItem.details || rawItem.summary || '',
      severity,
      publishedAt: normalizeDate(rawItem.published) || new Date(),
      updatedAt: normalizeDate(rawItem.modified),
      vendor,
      cveIds,
      references,
      tags: [],
      exploitStatus: 'unknown' as ExploitStatus,
      status: 'active' as AdvisoryStatus,
      rawPayload: rawItem,
      rawHash: generateHash(rawItem),
    };
  }
}
