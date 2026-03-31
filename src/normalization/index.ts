import { Normalizer, CisaKevNormalizer, OsvNormalizer } from './normalizers';

export function getNormalizerForSource(sourceName: string): Normalizer {
  switch (sourceName) {
    case 'cisa-kev':
      return new CisaKevNormalizer();
    case 'osv':
      return new OsvNormalizer();
    default:
      throw new Error(`No normalizer found for source: ${sourceName}`);
  }
}

export * from './normalizers';
