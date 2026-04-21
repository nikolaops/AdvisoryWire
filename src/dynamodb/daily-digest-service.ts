import { DynamoDBClient } from '@aws-sdk/client-dynamodb';
import { DynamoDBDocumentClient, GetCommand, PutCommand } from '@aws-sdk/lib-dynamodb';
import logger from '../logging';

const TABLE_NAME = process.env.DYNAMODB_TABLE ?? 'advisorywire';

const client = new DynamoDBClient({});
const ddb = DynamoDBDocumentClient.from(client);

export interface DigestEntry {
  externalId: string;
  cveIds: string[];
  severity: string;
  summary: string;
  title: string;
  referenceUrl?: string;
}

function todayKey(): string {
  return `DAILY_DIGEST#${new Date().toISOString().split('T')[0]}`;
}

function ttlIn48h(): number {
  return Math.floor(Date.now() / 1000) + 48 * 60 * 60;
}

/**
 * Appends new entries to today's digest accumulator and returns the full list.
 * Falls back to returning just the new entries on DynamoDB error.
 */
export async function loadAndAppendDailyDigest(newEntries: DigestEntry[]): Promise<DigestEntry[]> {
  const pk = todayKey();
  try {
    const result = await ddb.send(new GetCommand({
      TableName: TABLE_NAME,
      Key: { pk, sk: 'digest' },
    }));

    const existing: DigestEntry[] = result.Item?.entries
      ? (JSON.parse(result.Item.entries) as DigestEntry[])
      : [];

    // Avoid duplicates from retries
    const existingIds = new Set(existing.map(e => e.externalId));
    const toAdd = newEntries.filter(e => !existingIds.has(e.externalId));
    const updated = [...existing, ...toAdd];

    await ddb.send(new PutCommand({
      TableName: TABLE_NAME,
      Item: {
        pk,
        sk: 'digest',
        entries: JSON.stringify(updated),
        ttl: ttlIn48h(),
      },
    }));

    return updated;
  } catch (err) {
    logger.warn({ err }, 'Daily digest DynamoDB op failed, using current run entries only');
    return newEntries;
  }
}
