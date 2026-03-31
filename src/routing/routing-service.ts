import { NormalizedAdvisory, RoutingClass } from '../shared';
import { ScoringService } from '../scoring/scoring-service';
import logger from '../logging';

export interface RoutingDecision {
  advisory: NormalizedAdvisory;
  routingClass: RoutingClass;
  score: number;
  reason: string;
}

export class RoutingService {
  constructor(private scoringService: ScoringService) {}

  route(advisory: NormalizedAdvisory): RoutingDecision {
    const scoringResult = this.scoringService.score(advisory);

    logger.info(
      {
        externalId: advisory.externalId,
        source: advisory.source,
        routingClass: scoringResult.routingClass,
        score: scoringResult.score,
      },
      'Advisory routed'
    );

    return {
      advisory,
      routingClass: scoringResult.routingClass,
      score: scoringResult.score,
      reason: scoringResult.reason,
    };
  }
}
