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

const SOURCES = ['nvd', 'osv', 'github-advisory'] as const;
type SourceName = typeof SOURCES[number];

// EventBridge event—either a specific source or "all" (default)
interface LambdaEvent {
  source?: SourceName | 'all';
}

interface SourceResult {
  fetched: number;
  sent: number;
  deduped: number;
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

  // Inject optional API keys into process.env so connectors pick them up
  if (secrets.GITHUB_TOKEN) process.env.GITHUB_TOKEN = secrets.GITHUB_TOKEN;
  if (secrets.NVD_API_KEY) process.env.NVD_API_KEY = secrets.NVD_API_KEY;

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
      results[sourceName] = await processSource(sourceName, slackService);
    } catch (err) {
      logger.error({ source: sourceName, err }, 'Source processing failed');
      results[sourceName] = { fetched: 0, sent: 0, deduped: 0 };
    }
  }

  logger.info({ results }, 'Lambda run complete');
  return { statusCode: 200, results };
};

async function processSource(sourceName: SourceName, slackService: SlackService): Promise<SourceResult> {
  logger.info({ source: sourceName }, 'Processing source');

  const connector = connectors[sourceName];
  const normalizer = getNormalizerForSource(sourceName);

  // checkpoint = null means first run → establish baseline silently
  const checkpoint = await getCheckpoint(sourceName);

  const fetchResult = await connector.fetch(checkpoint ?? undefined);
  if (!fetchResult.success) {
    logger.warn({ source: sourceName, error: fetchResult.errorMessage }, 'Fetch failed');
    return { fetched: 0, sent: 0, deduped: 0 };
  }

  logger.info({ source: sourceName, count: fetchResult.items.length }, 'Fetch complete');

  if (checkpoint === null) {
    // First run: save baseline now but send nothing
    await saveCheckpoint(sourceName, new Date());
    logger.info({ source: sourceName }, 'First run baseline established, no alerts sent');
    return { fetched: fetchResult.items.length, sent: 0, deduped: 0 };
  }

  let sent = 0;
  let deduped = 0;

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
        const result = await slackService.sendInstantAlert(normalized);
        if (result.success) {
          sent++;
          logger.info(
            { externalId: normalized.externalId, source: sourceName },
            'Instant alert sent'
          );
        } else {
          logger.warn(
            { externalId: normalized.externalId, error: result.errorMessage },
            'Slack send failed'
          );
        }
      }
    } catch (err) {
      logger.error({ err, source: sourceName }, 'Failed to process advisory item');
    }
  }

  // Advance checkpoint to now
  await saveCheckpoint(sourceName, new Date());

  logger.info({ source: sourceName, sent, deduped }, 'Source processing done');
  return { fetched: fetchResult.items.length, sent, deduped };
}
