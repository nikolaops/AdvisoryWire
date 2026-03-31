import { Normalizer, CisaKevNormalizer, OsvNormalizer, GithubAdvisoryNormalizer } from './normalizers';

export function getNormalizerForSource(sourceName: string): Normalizer {
  switch (sourceName) {
    case 'cisa-kev':
      return new CisaKevNormalizer();
    case 'osv':
      return new OsvNormalizer();
    case 'github-advisory':
      return new GithubAdvisoryNormalizer();
    default:
      throw new Error(`No normalizer found for source: ${sourceName}`);
  }
}

export * from './normalizers';
