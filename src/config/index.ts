import dotenv from 'dotenv';

dotenv.config();

export interface Config {
  database: {
    host: string;
    port: number;
    database: string;
    user: string;
    password: string;
  };
  slack: {
    botToken: string;
    channelId: string;
  };
  app: {
    nodeEnv: string;
    logLevel: string;
    port: number;
  };
  polling: {
    githubAdvisoryInterval: string;
    osvInterval: string;
  };
  digest: {
    schedule: string;
    timezone: string;
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
  database: {
    host: getEnvVar('DATABASE_HOST', 'localhost'),
    port: parseInt(getEnvVar('DATABASE_PORT', '5432'), 10),
    database: getEnvVar('DATABASE_NAME', 'advisory_notifier'),
    user: getEnvVar('DATABASE_USER', 'postgres'),
    password: getEnvVar('DATABASE_PASSWORD'),
  },
  slack: {
    botToken: getEnvVar('SLACK_BOT_TOKEN'),
    channelId: getEnvVar('SLACK_CHANNEL_ID'),
  },
  app: {
    nodeEnv: getEnvVar('NODE_ENV', 'development'),
    logLevel: getEnvVar('LOG_LEVEL', 'info'),
    port: parseInt(getEnvVar('PORT', '3000'), 10),
  },
  polling: {
    githubAdvisoryInterval: getEnvVar('GITHUB_ADVISORY_POLL_INTERVAL', '0 */6 * * *'),
    osvInterval: getEnvVar('OSV_POLL_INTERVAL', '0 */6 * * *'),
  },
  digest: {
    schedule: getEnvVar('DIGEST_SCHEDULE', '0 9 * * *'),
    timezone: getEnvVar('DIGEST_TIMEZONE', 'UTC'),
  },
  routing: {
    instantAlertSeverities: getEnvVar('INSTANT_ALERT_SEVERITIES', 'critical,high').split(','),
    instantAlertIfExploited: getEnvVar('INSTANT_ALERT_IF_EXPLOITED', 'true') === 'true',
    digestSeverities: getEnvVar('DIGEST_SEVERITIES', 'medium,low').split(','),
  },
};
