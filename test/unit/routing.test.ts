import { RoutingService } from '../../src/routing/routing-service';
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

describe('RoutingService', () => {
  const scoringService = new ScoringService();
  const routingService = new RoutingService(scoringService);

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

  test('should route exploited vulnerability correctly', () => {
    const advisory = { ...baseAdvisory, exploitStatus: 'exploited' as const };
    
    const decision = routingService.route(advisory);

    expect(decision.routingClass).toBe('instant_alert');
    expect(decision.advisory).toEqual(advisory);
  });

  test('should route critical severity correctly', () => {
    const advisory = { ...baseAdvisory, severity: 'critical' as const };
    
    const decision = routingService.route(advisory);

    expect(decision.routingClass).toBe('instant_alert');
  });

  test('should route medium severity to digest', () => {
    const advisory = { ...baseAdvisory, severity: 'medium' as const };
    
    const decision = routingService.route(advisory);

    expect(decision.routingClass).toBe('digest');
  });
});
