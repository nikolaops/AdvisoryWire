import dotenv from 'dotenv';

dotenv.config();

export interface Config {
  dynamodb: {
    tableName: string;
    region: string;
  };
  slack: {
    botToken: string;
    channelId: string;
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
    region: getEnvVar('AWS_REGION', 'eu-west-1'),
  },
  slack: {
    botToken: getEnvVar('SLACK_BOT_TOKEN'),
    channelId: getEnvVar('SLACK_CHANNEL_ID'),
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
