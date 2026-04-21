import { NvdConnector } from '../connectors/nvd/nvd-connector';
import { OsvConnector } from '../connectors/osv/osv-connector';
import { GithubAdvisoryConnector } from '../connectors/github-advisory/github-advisory-connector';
import { getNormalizerForSource } from '../normalization';
import { ScoringService } from '../scoring/scoring-service';
import { RoutingService } from '../routing/routing-service';
import { SlackService } from '../notifications/slack/slack-service';
import { getCheckpoint, saveCheckpoint } from '../dynamodb/checkpoint-service';
import { checkAndMarkSeen } from '../dynamodb/dedup-service';
import { getSecrets } from '../secrets';
import { NormalizedAdvisory } from '../shared';
import logger from '../logging';

const SOURCES = ['osv', 'github-advisory', 'nvd'] as const;
type SourceName = typeof SOURCES[number];

// EventBridge event—either a specific source or "all" (default)
interface LambdaEvent {
  source?: SourceName | 'all';
}

interface SourceResult {
  fetched: number;
  queued: number;
  deduped: number;
  advisories: NormalizedAdvisory[];
}

const connectors: Record<SourceName, { fetch: (since?: Date) => Promise<any> }> = {
  nvd: new NvdConnector(),
  osv: new OsvConnector(),
  'github-advisory': new GithubAdvisoryConnector(),
};

const routingService = new RoutingService(new ScoringService());

// SlackService is initialized on first invocation (after secrets are loaded)
let slackService: SlackService | null = null;

export const handler = async (event: LambdaEvent) => {
  // Fetch secrets once per cold start — cached for warm invocations
  const secrets = await getSecrets();

  // Initialize SlackService lazily (reused across warm invocations)
  if (!slackService) {
    slackService = new SlackService(secrets.SLACK_BOT_TOKEN, secrets.SLACK_CHANNEL_ID);
  }

  const sourcesToRun: SourceName[] =
    event.source && event.source !== 'all'
      ? [event.source as SourceName]
      : [...SOURCES];

  const results: Record<string, SourceResult> = {};

  for (const sourceName of sourcesToRun) {
    try {
      results[sourceName] = await processSource(sourceName);
    } catch (err) {
      logger.error({ source: sourceName, err }, 'Source processing failed');
      results[sourceName] = { fetched: 0, queued: 0, deduped: 0, advisories: [] };
    }
  }

  const allAdvisories = Object.values(results).flatMap(r => r.advisories);
  let alertsSent = false;
  if (allAdvisories.length > 0) {
    try {
      const result = await slackService.sendThreadedBatch(allAdvisories);
      alertsSent = result.success;
      if (!result.success) {
        logger.error({ error: result.errorMessage }, 'Threaded batch failed');
      }
    } catch (err) {
      logger.error({ err }, 'Failed to send threaded batch');
    }
  }

  const summary = Object.fromEntries(
    Object.entries(results).map(([k, v]) => [k, { fetched: v.fetched, queued: v.queued, deduped: v.deduped }])
  );

  logger.info({ results: summary, alertsSent }, 'Lambda run complete');
  return { statusCode: 200, results: summary, alertsSent };
};

async function processSource(sourceName: SourceName): Promise<SourceResult> {
  logger.info({ source: sourceName }, 'Processing source');

  const connector = connectors[sourceName];
  const normalizer = getNormalizerForSource(sourceName);

  // checkpoint = null means first run → establish baseline silently
  const checkpoint = await getCheckpoint(sourceName);

  const fetchResult = await connector.fetch(checkpoint ?? undefined);
  if (!fetchResult.success) {
    logger.warn({ source: sourceName, error: fetchResult.errorMessage }, 'Fetch failed');
    return { fetched: 0, queued: 0, deduped: 0, advisories: [] };
  }

  logger.info({ source: sourceName, count: fetchResult.items.length }, 'Fetch complete');

  if (checkpoint === null) {
    await saveCheckpoint(sourceName, new Date());
    logger.info({ source: sourceName }, 'First run baseline established, no alerts sent');
    return { fetched: fetchResult.items.length, queued: 0, deduped: 0, advisories: [] };
  }

  let queued = 0;
  let deduped = 0;
  const advisories: NormalizedAdvisory[] = [];

  for (const rawItem of fetchResult.items) {
    try {
      const normalized: NormalizedAdvisory = normalizer.normalize(rawItem);

      // Skip advisories published more than 7 days ago (prevents flood on cold start)
      const daysSincePublished =
        (Date.now() - normalized.publishedAt.getTime()) / (1000 * 60 * 60 * 24);
      if (daysSincePublished > 7) {
        deduped++;
        continue;
      }

      // Cross-source dedup via DynamoDB (48h TTL)
      const alreadySeen = await checkAndMarkSeen(normalized.externalId, normalized.cveIds);
      if (alreadySeen) {
        deduped++;
        continue;
      }

      // Score + route
      const decision = routingService.route(normalized);

      if (decision.routingClass === 'instant_alert') {
        advisories.push(normalized);
        queued++;
        logger.info({ externalId: normalized.externalId, source: sourceName }, 'Advisory queued');
      }
    } catch (err) {
      logger.error({ err, source: sourceName }, 'Failed to process advisory item');
    }
  }

  // Advance checkpoint to now
  await saveCheckpoint(sourceName, new Date());

  logger.info({ source: sourceName, queued, deduped }, 'Source processing done');
  return { fetched: fetchResult.items.length, queued, deduped, advisories };
}
