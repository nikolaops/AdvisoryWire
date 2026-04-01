import { DynamoDBClient } from '@aws-sdk/client-dynamodb';
import { DynamoDBDocumentClient, GetCommand, PutCommand } from '@aws-sdk/lib-dynamodb';
import logger from '../logging';

const TABLE_NAME = process.env.DYNAMODB_TABLE ?? 'advisorywire';

const client = new DynamoDBClient({
  region: process.env.AWS_REGION ?? 'eu-west-1',
});
const ddb = DynamoDBDocumentClient.from(client);

/**
 * Get the last successful fetch timestamp for a source.
 * Returns null if never fetched (first run).
 */
export async function getCheckpoint(sourceName: string): Promise<Date | null> {
  try {
    const result = await ddb.send(new GetCommand({
      TableName: TABLE_NAME,
      Key: { pk: `CHECKPOINT#${sourceName}`, sk: 'checkpoint' },
    }));

    if (!result.Item?.lastFetchAt) return null;
    return new Date(result.Item.lastFetchAt);
  } catch (err) {
    logger.warn({ sourceName, err }, 'Failed to get checkpoint, treating as first run');
    return null;
  }
}

/**
 * Save the last successful fetch timestamp for a source.
 */
export async function saveCheckpoint(sourceName: string, fetchedAt: Date): Promise<void> {
  await ddb.send(new PutCommand({
    TableName: TABLE_NAME,
    Item: {
      pk: `CHECKPOINT#${sourceName}`,
      sk: 'checkpoint',
      lastFetchAt: fetchedAt.toISOString(),
    },
  }));
}
