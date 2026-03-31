import { SourceConnector } from '../connectors/base/connector';
import { SourceRepository } from '../persistence/repositories/source-repository';
import { SourceFetchRunRepository } from '../persistence/repositories/source-fetch-run-repository';
import { AdvisoryRepository } from '../persistence/repositories/advisory-repository';
import { NotificationRepository } from '../persistence/repositories/notification-repository';
import { getNormalizerForSource } from '../normalization';
import { DeduplicationService } from '../dedup/deduplication-service';
import { RoutingService } from '../routing/routing-service';
import { SlackService } from '../notifications/slack/slack-service';
import { config } from '../config';
import logger from '../logging';

export class PipelineOrchestrator {
  constructor(
    private sourceRepo: SourceRepository,
    private fetchRunRepo: SourceFetchRunRepository,
    private advisoryRepo: AdvisoryRepository,
    private notificationRepo: NotificationRepository,
    private dedupService: DeduplicationService,
    private routingService: RoutingService,
    private slackService: SlackService
  ) {}

  async processSource(connector: SourceConnector): Promise<void> {
    logger.info({ source: connector.name }, 'Starting source processing');

    // Get source record
    const source = await this.sourceRepo.findByName(connector.name);
    if (!source) {
      logger.error({ source: connector.name }, 'Source not found in database');
      return;
    }

    if (!source.enabled) {
      logger.info({ source: connector.name }, 'Source is disabled, skipping');
      return;
    }

    // Create fetch run record
    const fetchRunId = await this.fetchRunRepo.create(source.id, new Date());

    try {
      // Fetch data
      const sinceDate = source.lastSuccessAt || undefined;
      const fetchResult = await connector.fetch(sinceDate);

      if (!fetchResult.success) {
        await this.fetchRunRepo.updateFailure(fetchRunId, fetchResult.errorMessage || 'Unknown error');
        await this.sourceRepo.updateFailure(source.id, fetchResult.errorMessage || 'Unknown error');
        return;
      }

      logger.info(
        { source: connector.name, itemsFetched: fetchResult.items.length },
        'Source fetch completed'
      );

      // Process each item
      let processedCount = 0;
      for (const rawItem of fetchResult.items) {
        try {
          await this.processAdvisory(source.id, connector.name, rawItem);
          processedCount++;
        } catch (error) {
          logger.error(
            { error, source: connector.name, rawItem },
            'Failed to process individual advisory'
          );
          // Continue processing other items
        }
      }

      // Update fetch run and source
      await this.fetchRunRepo.updateSuccess(fetchRunId, fetchResult.items.length);
      await this.sourceRepo.updateSuccess(source.id);

      logger.info(
        { source: connector.name, processed: processedCount, total: fetchResult.items.length },
        'Source processing completed'
      );
    } catch (error: any) {
      const errorMessage = error?.message || String(error);
      logger.error({ error, source: connector.name }, 'Source processing failed');
      
      await this.fetchRunRepo.updateFailure(fetchRunId, errorMessage);
      await this.sourceRepo.updateFailure(source.id, errorMessage);
    }
  }

  private async processAdvisory(sourceId: number, sourceName: string, rawItem: any): Promise<void> {
    // Normalize
    const normalizer = getNormalizerForSource(sourceName);
    const normalized = normalizer.normalize(rawItem);

    logger.debug({ externalId: normalized.externalId, source: sourceName }, 'Advisory normalized');

    // Deduplicate
    const dedupResult = await this.dedupService.checkDuplication(
      sourceId,
      normalized.externalId,
      normalized.rawHash,
      normalized.cveIds
    );

    let advisoryId: number;

    if (dedupResult.isNew) {
      // Create new advisory
      advisoryId = await this.advisoryRepo.create(sourceId, normalized);
      logger.info({ advisoryId, externalId: normalized.externalId }, 'New advisory created');
    } else if (dedupResult.isDifferent && dedupResult.existingAdvisoryId) {
      // Update existing advisory
      advisoryId = dedupResult.existingAdvisoryId;
      await this.advisoryRepo.update(advisoryId, normalized);
      logger.info({ advisoryId, externalId: normalized.externalId }, 'Advisory updated');
    } else {
      // Exact duplicate, skip
      logger.debug({ externalId: normalized.externalId }, 'Exact duplicate, skipping');
      return;
    }

    // Only send instant alert for new advisories
    if (dedupResult.isNew) {
      // Route
      const routingDecision = this.routingService.route(normalized);

      // Skip instant alert for advisories published more than 7 days ago
      // This prevents notification floods when DB is fresh or app restarts
      const daysSincePublished = Math.floor(
        (Date.now() - normalized.publishedAt.getTime()) / (1000 * 60 * 60 * 24)
      );
      const isFresh = daysSincePublished <= 7;

      // Notify if instant alert and fresh
      if (routingDecision.routingClass === 'instant_alert' && isFresh) {
        await this.sendInstantNotification(advisoryId);
      } else if (!isFresh) {
        logger.debug(
          { externalId: normalized.externalId, daysSincePublished },
          'Advisory too old for instant alert, storing silently'
        );
      }
    }
  }

  private async sendInstantNotification(advisoryId: number): Promise<void> {
    try {
      // Check if already notified
      const alreadyNotified = await this.notificationRepo.hasBeenNotified(
        advisoryId,
        'instant_alert'
      );

      if (alreadyNotified) {
        logger.debug({ advisoryId }, 'Advisory already notified, skipping');
        return;
      }

      // Get full advisory
      const advisory = await this.advisoryRepo.findById(advisoryId);
      if (!advisory) {
        logger.warn({ advisoryId }, 'Advisory not found for notification');
        return;
      }

      // Send to Slack
      const result = await this.slackService.sendInstantAlert(advisory);

      // Record notification
      await this.notificationRepo.create(
        advisoryId,
        'instant_alert',
        config.slack.channelId,
        result.success ? 'sent' : 'failed',
        result.messageRef,
        result.errorMessage
      );
    } catch (error) {
      logger.error({ error, advisoryId }, 'Failed to send instant notification');
      
      await this.notificationRepo.create(
        advisoryId,
        'instant_alert',
        config.slack.channelId,
        'failed',
        null,
        error instanceof Error ? error.message : String(error)
      );
    }
  }
}
