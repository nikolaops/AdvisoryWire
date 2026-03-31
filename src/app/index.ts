import { config } from '../config';
import logger from '../logging';
import { runMigrations } from '../persistence/migrations/run-migrations';
import { createApiServer } from '../api';
import { Scheduler } from '../scheduler';
import { PipelineOrchestrator } from '../pipeline/orchestrator';
import { DigestService } from '../pipeline/digest-service';
import { SourceRepository } from '../persistence/repositories/source-repository';
import { SourceFetchRunRepository } from '../persistence/repositories/source-fetch-run-repository';
import { AdvisoryRepository } from '../persistence/repositories/advisory-repository';
import { NotificationRepository, DigestRunRepository } from '../persistence/repositories/notification-repository';
import { DeduplicationService } from '../dedup/deduplication-service';
import { ScoringService } from '../scoring/scoring-service';
import { RoutingService } from '../routing/routing-service';
import { SlackService } from '../notifications/slack/slack-service';
import { getConnectors } from '../connectors';
import { closePool } from '../persistence/database';

async function bootstrap() {
  logger.info('Starting Security Advisory Notifier');

  try {
    // Run database migrations
    logger.info('Running database migrations');
    await runMigrations();

    // Initialize repositories
    const sourceRepo = new SourceRepository();
    const fetchRunRepo = new SourceFetchRunRepository();
    const advisoryRepo = new AdvisoryRepository();
    const notificationRepo = new NotificationRepository();
    const digestRunRepo = new DigestRunRepository();

    // Initialize services
    const dedupService = new DeduplicationService(advisoryRepo);
    const scoringService = new ScoringService();
    const routingService = new RoutingService(scoringService);
    const slackService = new SlackService();

    // Initialize pipeline
    const orchestrator = new PipelineOrchestrator(
      sourceRepo,
      fetchRunRepo,
      advisoryRepo,
      notificationRepo,
      dedupService,
      routingService,
      slackService
    );

    const digestService = new DigestService(
      advisoryRepo,
      notificationRepo,
      digestRunRepo,
      slackService
    );

    // Start API server
    const app = createApiServer(sourceRepo);
    const server = app.listen(config.app.port, () => {
      logger.info({ port: config.app.port }, 'API server started');
    });

    // Start scheduler
    const scheduler = new Scheduler(orchestrator, digestService);
    scheduler.start();

    // Run initial fetch on startup
    logger.info('Running initial source fetch');
    const connectors = getConnectors();
    for (const connector of connectors) {
      try {
        await orchestrator.processSource(connector);
      } catch (error) {
        logger.error({ error, source: connector.name }, 'Initial fetch failed for source');
      }
    }

    // Handle shutdown
    const shutdown = async (signal: string) => {
      logger.info({ signal }, 'Shutting down gracefully');

      scheduler.stop();

      server.close(async () => {
        logger.info('API server closed');
        
        await closePool();
        logger.info('Database connections closed');

        process.exit(0);
      });

      // Force shutdown after 10 seconds
      setTimeout(() => {
        logger.error('Forced shutdown after timeout');
        process.exit(1);
      }, 10000);
    };

    process.on('SIGTERM', () => shutdown('SIGTERM'));
    process.on('SIGINT', () => shutdown('SIGINT'));

    logger.info('Application started successfully');
  } catch (error) {
    logger.error({ error }, 'Application startup failed');
    process.exit(1);
  }
}

bootstrap();
