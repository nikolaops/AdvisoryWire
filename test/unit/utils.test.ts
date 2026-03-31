import { generateHash, normalizeDate, normalizeSeverity } from '../../src/shared/utils';

describe('Utils', () => {
  describe('generateHash', () => {
    test('should generate consistent hash for same data', () => {
      const data = { key: 'value', number: 42 };
      
      const hash1 = generateHash(data);
      const hash2 = generateHash(data);

      expect(hash1).toBe(hash2);
      expect(hash1).toHaveLength(64); // SHA-256 hex
    });

    test('should generate different hashes for different data', () => {
      const data1 = { key: 'value1' };
      const data2 = { key: 'value2' };

      const hash1 = generateHash(data1);
      const hash2 = generateHash(data2);

      expect(hash1).not.toBe(hash2);
    });
  });

  describe('normalizeDate', () => {
    test('should parse valid ISO date string', () => {
      const date = normalizeDate('2024-01-15T10:30:00Z');

      expect(date).toBeInstanceOf(Date);
      expect(date?.toISOString()).toBe('2024-01-15T10:30:00.000Z');
    });

    test('should handle null input', () => {
      const date = normalizeDate(null);

      expect(date).toBeNull();
    });

    test('should handle invalid date string', () => {
      const date = normalizeDate('not-a-date');

      expect(date).toBeNull();
    });

    test('should handle Date object', () => {
      const inputDate = new Date('2024-01-15');
      const date = normalizeDate(inputDate);

      expect(date).toEqual(inputDate);
    });
  });

  describe('normalizeSeverity', () => {
    test('should normalize valid severity strings', () => {
      expect(normalizeSeverity('critical')).toBe('critical');
      expect(normalizeSeverity('HIGH')).toBe('high');
      expect(normalizeSeverity(' Medium ')).toBe('medium');
      expect(normalizeSeverity('low')).toBe('low');
    });

    test('should return unknown for invalid severities', () => {
      expect(normalizeSeverity('invalid')).toBe('unknown');
      expect(normalizeSeverity('')).toBe('unknown');
      expect(normalizeSeverity(null)).toBe('unknown');
      expect(normalizeSeverity(undefined)).toBe('unknown');
    });
  });
});
