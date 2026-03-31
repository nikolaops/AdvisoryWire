import { Normalizer, CisaKevNormalizer, OsvNormalizer, GithubAdvisoryNormalizer, NvdNormalizer } from './normalizers';

export function getNormalizerForSource(sourceName: string): Normalizer {
  switch (sourceName) {
    case 'cisa-kev':
      return new CisaKevNormalizer();
    case 'osv':
      return new OsvNormalizer();
    case 'github-advisory':
      return new GithubAdvisoryNormalizer();
    case 'nvd':
      return new NvdNormalizer();
    default:
      throw new Error(`No normalizer found for source: ${sourceName}`);
  }
}

export * from './normalizers';
