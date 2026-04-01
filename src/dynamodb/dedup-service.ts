import { DynamoDBClient } from '@aws-sdk/client-dynamodb';
import { DynamoDBDocumentClient, GetCommand, PutCommand } from '@aws-sdk/lib-dynamodb';
import logger from '../logging';

const TABLE_NAME = process.env.DYNAMODB_TABLE ?? 'advisorywire';
// TTL: 48 hours - enough to deduplicate across sources within same poll window
const TTL_SECONDS = 48 * 60 * 60;

const client = new DynamoDBClient({});
const ddb = DynamoDBDocumentClient.from(client);

/**
 * Returns true if this advisory ID has been seen (already sent to Slack).
 * Uses a composite key: source-specific ID + any CVE aliases.
 */
export async function hasBeenSeen(advisoryId: string): Promise<boolean> {
  try {
    const result = await ddb.send(new GetCommand({
      TableName: TABLE_NAME,
      Key: { pk: `SEEN#${advisoryId}`, sk: 'seen' },
    }));
    return !!result.Item;
  } catch (err) {
    logger.warn({ advisoryId, err }, 'Dedup check failed, treating as unseen');
    return false;
  }
}

/**
 * Mark advisory ID as seen with TTL.
 */
export async function markAsSeen(advisoryId: string): Promise<void> {
  const ttl = Math.floor(Date.now() / 1000) + TTL_SECONDS;
  await ddb.send(new PutCommand({
    TableName: TABLE_NAME,
    Item: {
      pk: `SEEN#${advisoryId}`,
      sk: 'seen',
      seenAt: new Date().toISOString(),
      ttl,
    },
  }));
}

/**
 * Check and mark multiple IDs at once (externalId + CVE aliases).
 * Returns true if ANY of the IDs has been seen (prevents cross-source duplicates).
 */
export async function checkAndMarkSeen(externalId: string, cveIds: string[]): Promise<boolean> {
  const allIds = [externalId, ...cveIds];

  for (const id of allIds) {
    if (await hasBeenSeen(id)) {
      logger.debug({ externalId, matchedId: id }, 'Advisory already seen (dedup)');
      return true;
    }
  }

  // Mark all IDs as seen
  await Promise.all(allIds.map(id => markAsSeen(id)));
  return false;
}
