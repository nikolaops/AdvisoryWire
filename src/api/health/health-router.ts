import express, { Request, Response } from 'express';
import { checkConnection } from '../../persistence/database';
import { SourceRepository, Source } from '../../persistence/repositories/source-repository';
import logger from '../../logging';

export function createHealthRouter(sourceRepo: SourceRepository): express.Router {
  const router = express.Router();

  // Liveness probe
  router.get('/live', (req: Request, res: Response) => {
    res.status(200).json({
      status: 'ok',
      timestamp: new Date().toISOString(),
    });
  });

  // Readiness probe
  router.get('/ready', async (req: Request, res: Response) => {
    try {
      // Check database connection
      const dbHealthy = await checkConnection();

      if (!dbHealthy) {
        res.status(503).json({
          status: 'not_ready',
          database: 'unhealthy',
          timestamp: new Date().toISOString(),
        });
        return;
      }

      // Check sources status
      const sources = await sourceRepo.findAllEnabled();
      const sourceStatus = sources.map((source: Source) => ({
        name: source.name,
        lastSuccess: source.lastSuccessAt,
        lastFailure: source.lastFailureAt,
      }));

      res.status(200).json({
        status: 'ready',
        database: 'healthy',
        sources: sourceStatus,
        timestamp: new Date().toISOString(),
      });
    } catch (error) {
      logger.error({ error }, 'Health check failed');
      
      res.status(503).json({
        status: 'not_ready',
        error: error instanceof Error ? error.message : String(error),
        timestamp: new Date().toISOString(),
      });
    }
  });

  return router;
}
