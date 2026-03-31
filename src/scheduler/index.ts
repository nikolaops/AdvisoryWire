import cron from 'node-cron';
import { getConnectors } from '../connectors';
import { PipelineOrchestrator } from '../pipeline/orchestrator';
import { DigestService } from '../pipeline/digest-service';
import { config } from '../config';
import logger from '../logging';

export class Scheduler {
  private jobs: cron.ScheduledTask[] = [];

  constructor(
    private orchestrator: PipelineOrchestrator,
    private digestService: DigestService
  ) {}

  start(): void {
    logger.info('Starting scheduler');

    const connectors = getConnectors();

    // Schedule GitHub Advisory polling
    const githubConnector = connectors.find(c => c.name === 'github-advisory');
    if (githubConnector) {
      const githubJob = cron.schedule(
        config.polling.githubAdvisoryInterval,
        () => {
          logger.info('GitHub Advisory scheduled job triggered');
          this.orchestrator.processSource(githubConnector).catch(error => {
            logger.error({ error }, 'GitHub Advisory processing failed');
          });
        },
        {
          timezone: config.digest.timezone,
        }
      );
      this.jobs.push(githubJob);
      logger.info({ schedule: config.polling.githubAdvisoryInterval }, 'GitHub Advisory polling scheduled');
    }

    // Schedule OSV polling
    const osvConnector = connectors.find(c => c.name === 'osv');
    if (osvConnector) {
      const osvJob = cron.schedule(
        config.polling.osvInterval,
        () => {
          logger.info('OSV scheduled job triggered');
          this.orchestrator.processSource(osvConnector).catch(error => {
            logger.error({ error }, 'OSV processing failed');
          });
        },
        {
          timezone: config.digest.timezone,
        }
      );
      this.jobs.push(osvJob);
      logger.info({ schedule: config.polling.osvInterval }, 'OSV polling scheduled');
    }

    // Schedule NVD polling
    const nvdConnector = connectors.find(c => c.name === 'nvd');
    if (nvdConnector) {
      const nvdJob = cron.schedule(
        config.polling.nvdInterval,
        () => {
          logger.info('NVD scheduled job triggered');
          this.orchestrator.processSource(nvdConnector).catch(error => {
            logger.error({ error }, 'NVD processing failed');
          });
        },
        {
          timezone: config.digest.timezone,
        }
      );
      this.jobs.push(nvdJob);
      logger.info({ schedule: config.polling.nvdInterval }, 'NVD polling scheduled');
    }

    // Schedule daily digest
    const digestJob = cron.schedule(
      config.digest.schedule,
      () => {
        logger.info('Daily digest scheduled job triggered');
        this.digestService.runDigest().catch(error => {
          logger.error({ error }, 'Daily digest failed');
        });
      },
      {
        timezone: config.digest.timezone,
      }
    );
    this.jobs.push(digestJob);
    logger.info({ schedule: config.digest.schedule }, 'Daily digest scheduled');

    logger.info('All scheduled jobs started');
  }

  stop(): void {
    logger.info('Stopping scheduler');
    this.jobs.forEach(job => job.stop());
    this.jobs = [];
  }
}
