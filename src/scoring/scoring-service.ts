import { NormalizedAdvisory, ScoringResult, RoutingClass } from '../shared';
import { config } from '../config';
import logger from '../logging';

export class ScoringService {
  score(advisory: NormalizedAdvisory): ScoringResult {
    let score = 0;
    let routingClass: RoutingClass = 'ignore';
    const reasons: string[] = [];

    // Check exploit status
    if (advisory.exploitStatus === 'exploited' && config.routing.instantAlertIfExploited) {
      score += 100;
      reasons.push('exploited');
      routingClass = 'instant_alert';
    }

    // Check severity
    if (config.routing.instantAlertSeverities.includes(advisory.severity)) {
      score += 50;
      reasons.push(`severity:${advisory.severity}`);
      routingClass = 'instant_alert';
    } else if (config.routing.digestSeverities.includes(advisory.severity)) {
      score += 20;
      reasons.push(`severity:${advisory.severity}`);
      
      // Only set to digest if not already set to instant_alert
      if (routingClass !== 'instant_alert') {
        routingClass = 'digest';
      }
    }

    // Recency bonus (within last 7 days)
    const daysSincePublished = Math.floor(
      (Date.now() - advisory.publishedAt.getTime()) / (1000 * 60 * 60 * 24)
    );
    
    if (daysSincePublished <= 7) {
      score += 10;
      reasons.push('recent');
    }

    // If still unknown/ignored, default to digest
    if (routingClass === 'ignore' && advisory.severity !== 'unknown') {
      routingClass = 'digest';
      reasons.push('default:digest');
    }

    logger.debug(
      { 
        externalId: advisory.externalId, 
        score, 
        routingClass, 
        reasons 
      },
      'Advisory scored'
    );

    return {
      score,
      routingClass,
      reason: reasons.join(', '),
    };
  }
}
