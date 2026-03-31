import { createHash } from 'crypto';

export function generateHash(data: any): string {
  const json = JSON.stringify(data);
  return createHash('sha256').update(json).digest('hex');
}

export function normalizeDate(date: string | Date | null): Date | null {
  if (!date) return null;
  try {
    const parsed = new Date(date);
    return isNaN(parsed.getTime()) ? null : parsed;
  } catch {
    return null;
  }
}

export function normalizeSeverity(severity: string | null | undefined): 'critical' | 'high' | 'medium' | 'low' | 'unknown' {
  if (!severity) return 'unknown';
  
  const normalized = severity.toLowerCase().trim();
  
  if (['critical', 'high', 'medium', 'low'].includes(normalized)) {
    return normalized as 'critical' | 'high' | 'medium' | 'low';
  }
  
  return 'unknown';
}

export function sleep(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms));
}
