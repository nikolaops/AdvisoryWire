import { SecretsManagerClient, GetSecretValueCommand } from '@aws-sdk/client-secrets-manager';
import logger from '../logging';

export interface AdvisoryWireSecrets {
  SLACK_BOT_TOKEN: string;
  SLACK_CHANNEL_ID: string;
  GITHUB_TOKEN?: string;
  NVD_API_KEY?: string;
}

// Cached per Lambda container lifetime (cold start fetches once, warm invocations reuse)
let cachedSecrets: AdvisoryWireSecrets | null = null;

const client = new SecretsManagerClient({});

export async function getSecrets(): Promise<AdvisoryWireSecrets> {
  if (cachedSecrets) return cachedSecrets;

  const secretName = process.env.ADVISORYWIRE_SECRET_NAME ?? 'advisorywire';
  logger.info({ secretName }, 'Fetching secrets from Secrets Manager');

  const response = await client.send(
    new GetSecretValueCommand({ SecretId: secretName })
  );

  if (!response.SecretString) {
    throw new Error(`Secret '${secretName}' has no SecretString value`);
  }

  cachedSecrets = JSON.parse(response.SecretString) as AdvisoryWireSecrets;

  if (!cachedSecrets.SLACK_BOT_TOKEN || !cachedSecrets.SLACK_CHANNEL_ID) {
    throw new Error(`Secret '${secretName}' is missing required keys: SLACK_BOT_TOKEN, SLACK_CHANNEL_ID`);
  }

  return cachedSecrets;
}
