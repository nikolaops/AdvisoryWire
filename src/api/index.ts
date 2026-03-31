import express from 'express';
import { config } from '../config';
import { createHealthRouter } from './health/health-router';
import { SourceRepository } from '../persistence/repositories/source-repository';
import logger from '../logging';

export function createApiServer(sourceRepo: SourceRepository): express.Application {
  const app = express();

  app.use(express.json());

  // Request logging middleware
  app.use((req, res, next) => {
    logger.info({ method: req.method, path: req.path }, 'API request');
    next();
  });

  // Health routes
  app.use('/health', createHealthRouter(sourceRepo));

  // Root endpoint
  app.get('/', (req, res) => {
    res.json({
      name: 'Security Advisory Notifier',
      version: '1.0.0',
      status: 'running',
    });
  });

  // Error handler
  app.use((err: any, req: express.Request, res: express.Response, next: express.NextFunction) => {
    logger.error({ error: err }, 'API error');
    res.status(500).json({
      error: 'Internal server error',
      message: config.app.nodeEnv === 'development' ? err.message : undefined,
    });
  });

  return app;
}
