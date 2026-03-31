import { CisaKevNormalizer, OsvNormalizer } from '../../src/normalization/normalizers';

describe('CisaKevNormalizer', () => {
  const normalizer = new CisaKevNormalizer();

  test('should normalize CISA KEV item correctly', () => {
    const rawItem = {
      cveID: 'CVE-2024-1234',
      vendorProject: 'TestVendor',
      product: 'TestProduct',
      vulnerabilityName: 'Test Vulnerability',
      dateAdded: '2024-01-15',
      shortDescription: 'A test vulnerability description',
      requiredAction: 'Apply patch',
      dueDate: '2024-02-15',
      knownRansomwareCampaignUse: 'Known',
    };

    const result = normalizer.normalize(rawItem);

    expect(result.externalId).toBe('CVE-2024-1234');
    expect(result.source).toBe('cisa-kev');
    expect(result.title).toBe('Test Vulnerability');
    expect(result.summary).toBe('A test vulnerability description');
    expect(result.severity).toBe('high');
    expect(result.vendor).toBe('TestVendor');
    expect(result.cveIds).toEqual(['CVE-2024-1234']);
    expect(result.exploitStatus).toBe('exploited');
    expect(result.tags).toContain('ransomware');
    expect(result.rawHash).toBeDefined();
  });

  test('should handle missing optional fields', () => {
    const rawItem = {
      cveID: 'CVE-2024-5678',
      dateAdded: '2024-01-20',
      shortDescription: 'Brief description',
      knownRansomwareCampaignUse: 'Unknown',
    };

    const result = normalizer.normalize(rawItem);

    expect(result.externalId).toBe('CVE-2024-5678');
    expect(result.vendor).toBeNull();
    expect(result.tags).toEqual([]);
  });
});

describe('OsvNormalizer', () => {
  const normalizer = new OsvNormalizer();

  test('should normalize OSV item correctly', () => {
    const rawItem = {
      id: 'OSV-2024-001',
      summary: 'Test OSV Advisory',
      details: 'Detailed description of the vulnerability',
      severity: [
        {
          type: 'CVSS_V3',
          score: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/7.5',
        },
      ],
      published: '2024-01-10T00:00:00Z',
      modified: '2024-01-15T00:00:00Z',
      affected: [
        {
          package: {
            name: 'test-package',
            ecosystem: 'npm',
          },
        },
      ],
      references: [
        {
          type: 'WEB',
          url: 'https://example.com/advisory',
        },
      ],
      aliases: ['CVE-2024-9999'],
    };

    const result = normalizer.normalize(rawItem);

    expect(result.externalId).toBe('OSV-2024-001');
    expect(result.source).toBe('osv');
    expect(result.title).toBe('Test OSV Advisory');
    expect(result.severity).toBe('high');
    expect(result.cveIds).toEqual(['CVE-2024-9999']);
    expect(result.references.length).toBe(1);
    expect(result.rawHash).toBeDefined();
  });

  test('should default unknown severity when no CVSS available', () => {
    const rawItem = {
      id: 'OSV-2024-002',
      summary: 'Another advisory',
      published: '2024-01-10T00:00:00Z',
    };

    const result = normalizer.normalize(rawItem);

    expect(result.severity).toBe('unknown');
  });
});
