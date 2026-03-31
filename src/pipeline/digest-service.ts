import { AdvisoryRepository } from '../persistence/repositories/advisory-repository';
import { NotificationRepository, DigestRunRepository } from '../persistence/repositories/notification-repository';
import { SlackService } from '../notifications/slack/slack-service';
import { config } from '../config';
import logger from '../logging';

export class DigestService {
  constructor(
    private advisoryRepo: AdvisoryRepository,
    private notificationRepo: NotificationRepository,
    private digestRunRepo: DigestRunRepository,
    private slackService: SlackService
  ) {}

  async runDigest(): Promise<void> {
    logger.info('Starting daily digest');

    const digestRunId = await this.digestRunRepo.create(new Date());

    try {
      // Find all advisories not yet included in instant alerts or digest
      const advisories = await this.advisoryRepo.findNotNotified('digest', 100);

      logger.info({ count: advisories.length }, 'Found advisories for digest');

      // Filter to only digest-eligible severities
      const digestEligible = advisories.filter(adv =>
        config.routing.digestSeverities.includes(adv.severity)
      );

      logger.info({ count: digestEligible.length }, 'Digest-eligible advisories');

      if (digestEligible.length === 0) {
        await this.digestRunRepo.updateSuccess(digestRunId, 0, null);
        logger.info('No advisories for digest');
        return;
      }

      // Send digest
      const result = await this.slackService.sendDigest(digestEligible);

      if (result.success) {
        // Mark all advisories as notified
        for (const advisory of digestEligible) {
          await this.notificationRepo.create(
            advisory.id,
            'digest',
            config.slack.channelId,
            'sent',
            result.messageRef,
            null
          );
        }

        await this.digestRunRepo.updateSuccess(digestRunId, digestEligible.length, result.messageRef ?? null);
        logger.info({ count: digestEligible.length }, 'Digest completed successfully');
      } else {
        await this.digestRunRepo.updateFailure(digestRunId, result.errorMessage ?? 'Unknown error');
        logger.error({ error: result.errorMessage }, 'Digest failed');
      }
    } catch (error: any) {
      const errorMessage = error?.message || String(error);
      logger.error({ error }, 'Digest processing failed');
      
      await this.digestRunRepo.updateFailure(digestRunId, errorMessage);
    }
  }
}
