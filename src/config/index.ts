import dotenv from 'dotenv';

dotenv.config();

export interface Config {
  dynamodb: {
    tableName: string;
  };
  app: {
    nodeEnv: string;
    logLevel: string;
  };
  routing: {
    instantAlertSeverities: string[];
    instantAlertIfExploited: boolean;
    digestSeverities: string[];
  };
}

function getEnvVar(key: string, defaultValue?: string): string {
  const value = process.env[key] || defaultValue;
  if (!value) {
    throw new Error(`Missing required environment variable: ${key}`);
  }
  return value;
}

export const config: Config = {
  dynamodb: {
    tableName: getEnvVar('DYNAMODB_TABLE', 'advisorywire'),
  },
  app: {
    nodeEnv: getEnvVar('NODE_ENV', 'production'),
    logLevel: getEnvVar('LOG_LEVEL', 'info'),
  },
  routing: {
    instantAlertSeverities: getEnvVar('INSTANT_ALERT_SEVERITIES', 'critical,high').split(','),
    instantAlertIfExploited: getEnvVar('INSTANT_ALERT_IF_EXPLOITED', 'true') === 'true',
    digestSeverities: getEnvVar('DIGEST_SEVERITIES', 'medium,low').split(','),
  },
};
