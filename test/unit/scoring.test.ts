import { ScoringService } from '../../src/scoring/scoring-service';
import { NormalizedAdvisory } from '../../src/shared/types';

// Mock config
jest.mock('../../src/config', () => ({
  config: {
    routing: {
      instantAlertSeverities: ['critical', 'high'],
      instantAlertIfExploited: true,
      digestSeverities: ['medium', 'low'],
    },
  },
}));

describe('ScoringService', () => {
  const scoringService = new ScoringService();

  const baseAdvisory: NormalizedAdvisory = {
    externalId: 'TEST-001',
    source: 'test',
    title: 'Test Advisory',
    summary: 'Test summary',
    severity: 'medium',
    publishedAt: new Date(),
    updatedAt: null,
    vendor: null,
    cveIds: [],
    references: [],
    tags: [],
    exploitStatus: 'unknown',
    status: 'active',
    rawPayload: {},
    rawHash: 'hash',
  };

  test('should route exploited advisories to instant alert', () => {
    const advisory = { ...baseAdvisory, exploitStatus: 'exploited' as const };
    
    const result = scoringService.score(advisory);

    expect(result.routingClass).toBe('instant_alert');
    expect(result.score).toBeGreaterThan(50);
    expect(result.reason).toContain('exploited');
  });

  test('should route critical severity to instant alert', () => {
    const advisory = { ...baseAdvisory, severity: 'critical' as const };
    
    const result = scoringService.score(advisory);

    expect(result.routingClass).toBe('instant_alert');
    expect(result.reason).toContain('severity:critical');
  });

  test('should route high severity to instant alert', () => {
    const advisory = { ...baseAdvisory, severity: 'high' as const };
    
    const result = scoringService.score(advisory);

    expect(result.routingClass).toBe('instant_alert');
    expect(result.reason).toContain('severity:high');
  });

  test('should route medium severity to digest', () => {
    const advisory = { ...baseAdvisory, severity: 'medium' as const };
    
    const result = scoringService.score(advisory);

    expect(result.routingClass).toBe('digest');
    expect(result.reason).toContain('severity:medium');
  });

  test('should route low severity to digest', () => {
    const advisory = { ...baseAdvisory, severity: 'low' as const };
    
    const result = scoringService.score(advisory);

    expect(result.routingClass).toBe('digest');
    expect(result.reason).toContain('severity:low');
  });

  test('should add recency bonus for recent advisories', () => {
    const recentDate = new Date();
    recentDate.setDate(recentDate.getDate() - 3); // 3 days ago
    
    const advisory = { ...baseAdvisory, publishedAt: recentDate, severity: 'medium' as const };
    
    const result = scoringService.score(advisory);

    expect(result.reason).toContain('recent');
  });
});
