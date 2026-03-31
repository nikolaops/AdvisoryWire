import { NormalizedAdvisory, Severity, ExploitStatus, AdvisoryStatus, generateHash, normalizeDate, normalizeSeverity } from '../shared';

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

export class GithubAdvisoryNormalizer implements Normalizer {
  normalize(rawItem: any): NormalizedAdvisory {
    const ghsaId: string = rawItem.ghsa_id || 'UNKNOWN';
    const cveId: string | null = rawItem.cve_id || null;
    const cveIds: string[] = cveId ? [cveId] : [];

    // GitHub Advisory has direct severity string: low, medium, high, critical
    const severity: Severity = normalizeSeverity(rawItem.severity || 'unknown');

    // CVSS score from the cvss object
    const cvssScore: number | null = rawItem.cvss?.score ?? null;

    // References are plain strings
    const references = (rawItem.references || []).map((url: string) => ({ url, label: null }));
    if (rawItem.html_url) {
      references.unshift({ url: rawItem.html_url, label: 'GitHub Advisory' });
    }

    // Vendor from first affected package ecosystem
    const vendor: string | null = rawItem.vulnerabilities?.[0]?.package?.ecosystem ?? null;

    // GitHub Advisory database does not flag exploit_status directly
    // but CRITICAL severity advisories in GHSA are almost always actively exploited
    const exploitStatus: ExploitStatus = cvssScore !== null && cvssScore >= 9.0
      ? 'exploited'
      : 'unknown';

    return {
      externalId: ghsaId,
      source: 'github-advisory',
      title: rawItem.summary || `${ghsaId}`,
      summary: rawItem.description || rawItem.summary || '',
      severity,
      publishedAt: normalizeDate(rawItem.published_at) || new Date(),
      updatedAt: normalizeDate(rawItem.updated_at),
      vendor,
      cveIds,
      references,
      tags: (rawItem.cwes || []).map((c: any) => c.cwe_id),
      exploitStatus,
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
    
    // Determine severity - prefer database_specific.severity string (e.g. "HIGH", "CRITICAL")
    let severity: Severity = 'unknown';
    const dbSeverityStr: string | undefined = rawItem.database_specific?.severity;
    if (dbSeverityStr && typeof dbSeverityStr === 'string') {
      severity = normalizeSeverity(dbSeverityStr.toLowerCase());
    } else if (rawItem.severity && rawItem.severity.length > 0) {
      // OSV severity score field is a full CVSS vector string (e.g. "CVSS:3.1/AV:N/..."), not a number.
      // Try database_specific.cvss.base_score if present (some sources include it)
      const baseScore: number | undefined = rawItem.database_specific?.cvss?.base_score
        ?? rawItem.database_specific?.cvss?.baseScore;
      if (baseScore !== undefined) {
        const s = parseFloat(String(baseScore));
        if (s >= 9.0) severity = 'critical';
        else if (s >= 7.0) severity = 'high';
        else if (s >= 4.0) severity = 'medium';
        else severity = 'low';
      } else {
        // Fall back to CVSS_V4 or CVSS_V3 vector heuristic
        const cvss = rawItem.severity.find((s: any) => s.type === 'CVSS_V3' || s.type === 'CVSS_V4');
        if (cvss) {
          // Heuristic: check C/I/A metric values in the vector; all H = critical, mix = high, etc.
          const vector: string = cvss.score || '';
          const criticalCount = (vector.match(/:[CH]/g) || []).length;
          if (criticalCount >= 3) severity = 'critical';
          else if (criticalCount >= 2) severity = 'high';
          else severity = 'medium';
        }
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

export class NvdNormalizer implements Normalizer {
  normalize(rawItem: any): NormalizedAdvisory {
    const cveId: string = rawItem.id || 'UNKNOWN';

    // Pick best available CVSS score: V3.1 > V3.0 > V2
    let severity: Severity = 'unknown';
    let cvssScore: number | null = null;
    let cvssVector: string | null = null;

    const v31 = rawItem.metrics?.cvssMetricV31?.[0];
    const v30 = rawItem.metrics?.cvssMetricV30?.[0];
    const v2 = rawItem.metrics?.cvssMetricV2?.[0];

    if (v31) {
      cvssScore = v31.cvssData.baseScore;
      cvssVector = v31.cvssData.vectorString;
      severity = normalizeSeverity(v31.cvssData.baseSeverity);
    } else if (v30) {
      cvssScore = v30.cvssData.baseScore;
      cvssVector = v30.cvssData.vectorString;
      severity = normalizeSeverity(v30.cvssData.baseSeverity);
    } else if (v2) {
      cvssScore = v2.cvssData.baseScore;
      cvssVector = v2.cvssData.vectorString;
      severity = normalizeSeverity(v2.baseSeverity);
    }

    // CISA KEV flag - NVD includes cisaExploitAdd date when CVE is in KEV
    const exploitStatus: ExploitStatus = rawItem.cisaExploitAdd ? 'exploited' : 'unknown';

    const description = rawItem.descriptions?.find((d: any) => d.lang === 'en')?.value ?? '';

    const references = (rawItem.references ?? []).map((ref: any) => ({
      url: ref.url,
      label: ref.tags?.[0] ?? null,
    }));
    references.unshift({
      url: `https://nvd.nist.gov/vuln/detail/${cveId}`,
      label: 'NVD',
    });

    const tags: string[] = [];
    if (rawItem.cisaExploitAdd) tags.push('cisa-kev');
    if (cvssScore !== null && cvssScore >= 9.0) tags.push('critical-cvss');

    return {
      externalId: cveId,
      source: 'nvd',
      title: rawItem.cisaVulnerabilityName || description.substring(0, 120) || cveId,
      summary: description,
      severity,
      publishedAt: normalizeDate(rawItem.published) || new Date(),
      updatedAt: normalizeDate(rawItem.lastModified),
      vendor: rawItem.sourceIdentifier ?? null,
      cveIds: [cveId],
      references,
      tags,
      exploitStatus,
      status: 'active' as AdvisoryStatus,
      rawPayload: rawItem,
      rawHash: generateHash(rawItem),
    };
  }
}
