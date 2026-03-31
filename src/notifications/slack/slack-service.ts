import { WebClient } from '@slack/web-api';
import { config } from '../../config';
import { StoredAdvisory } from '../../shared/types';
import logger from '../../logging';

export interface SlackMessageResult {
  success: boolean;
  messageRef?: string;
  errorMessage?: string;
}

export class SlackService {
  private client: WebClient;

  constructor() {
    this.client = new WebClient(config.slack.botToken);
  }

  async sendInstantAlert(advisory: StoredAdvisory): Promise<SlackMessageResult> {
    try {
      logger.info({ advisoryId: advisory.id, externalId: advisory.externalId }, 'Sending instant alert');

      const blocks = this.buildInstantAlertBlocks(advisory);

      const response = await this.client.chat.postMessage({
        channel: config.slack.channelId,
        text: `🚨 Security Advisory: ${advisory.title}`,
        blocks,
      });

      if (response.ok && response.ts) {
        logger.info(
          { advisoryId: advisory.id, messageTs: response.ts },
          'Instant alert sent successfully'
        );

        return {
          success: true,
          messageRef: response.ts,
        };
      } else {
        const errorMessage = `Slack API returned not ok: ${response.error}`;
        logger.error({ advisoryId: advisory.id, error: response.error }, 'Slack message failed');
        
        return {
          success: false,
          errorMessage,
        };
      }
    } catch (error: any) {
      const errorMessage = error?.message || String(error);
      logger.error({ error, advisoryId: advisory.id }, 'Failed to send instant alert');
      
      return {
        success: false,
        errorMessage,
      };
    }
  }

  async sendDigest(advisories: StoredAdvisory[]): Promise<SlackMessageResult> {
    try {
      logger.info({ count: advisories.length }, 'Sending daily digest');

      if (advisories.length === 0) {
        logger.info('No advisories for digest, skipping');
        return { success: true };
      }

      const blocks = this.buildDigestBlocks(advisories);

      const response = await this.client.chat.postMessage({
        channel: config.slack.channelId,
        text: `📋 Daily Security Advisory Digest (${advisories.length} items)`,
        blocks,
      });

      if (response.ok && response.ts) {
        logger.info({ messageTs: response.ts, count: advisories.length }, 'Digest sent successfully');

        return {
          success: true,
          messageRef: response.ts,
        };
      } else {
        const errorMessage = `Slack API returned not ok: ${response.error}`;
        logger.error({ error: response.error }, 'Digest message failed');
        
        return {
          success: false,
          errorMessage,
        };
      }
    } catch (error: any) {
      const errorMessage = error?.message || String(error);
      logger.error({ error }, 'Failed to send digest');
      
      return {
        success: false,
        errorMessage,
      };
    }
  }

  private buildInstantAlertBlocks(advisory: StoredAdvisory): any[] {
    const severityEmoji = {
      critical: '🔴',
      high: '🟠',
      medium: '🟡',
      low: '🟢',
      unknown: '⚪',
    };

    const exploitEmoji = advisory.exploitStatus === 'exploited' ? '💥 EXPLOITED' : '';

    const identifiers = advisory.cveIds.length > 0 
      ? advisory.cveIds.join(', ') 
      : advisory.externalId;

    const blocks: any[] = [
      {
        type: 'header',
        text: {
          type: 'plain_text',
          text: `🚨 Security Advisory`,
        },
      },
      {
        type: 'section',
        text: {
          type: 'mrkdwn',
          text: `*${advisory.title}*`,
        },
      },
      {
        type: 'section',
        fields: [
          {
            type: 'mrkdwn',
            text: `*Severity:*\n${severityEmoji[advisory.severity]} ${advisory.severity.toUpperCase()}`,
          },
          {
            type: 'mrkdwn',
            text: `*Source:*\n${advisory.source}`,
          },
          {
            type: 'mrkdwn',
            text: `*Identifiers:*\n${identifiers}`,
          },
          {
            type: 'mrkdwn',
            text: `*Published:*\n${advisory.publishedAt.toISOString().split('T')[0]}`,
          },
        ],
      },
    ];

    if (exploitEmoji) {
      blocks.push({
        type: 'section',
        text: {
          type: 'mrkdwn',
          text: `*⚠️ Status:* ${exploitEmoji}`,
        },
      });
    }

    if (advisory.summary) {
      blocks.push({
        type: 'section',
        text: {
          type: 'mrkdwn',
          text: `*Summary:*\n${advisory.summary.substring(0, 500)}${advisory.summary.length > 500 ? '...' : ''}`,
        },
      });
    }

    if (advisory.references.length > 0) {
      const refText = advisory.references
        .slice(0, 3)
        .map(ref => `• <${ref.url}|${ref.label || ref.url}>`)
        .join('\n');

      blocks.push({
        type: 'section',
        text: {
          type: 'mrkdwn',
          text: `*References:*\n${refText}`,
        },
      });
    }

    blocks.push({
      type: 'divider',
    });

    return blocks;
  }

  private buildDigestBlocks(advisories: StoredAdvisory[]): any[] {
    const blocks: any[] = [
      {
        type: 'header',
        text: {
          type: 'plain_text',
          text: `📋 Daily Security Advisory Digest`,
        },
      },
      {
        type: 'section',
        text: {
          type: 'mrkdwn',
          text: `*${advisories.length} security advisories* from the last 24 hours:`,
        },
      },
      {
        type: 'divider',
      },
    ];

    // Group by severity
    const bySeverity: Record<string, StoredAdvisory[]> = {
      critical: [],
      high: [],
      medium: [],
      low: [],
      unknown: [],
    };

    advisories.forEach(adv => {
      bySeverity[adv.severity].push(adv);
    });

    for (const [severity, items] of Object.entries(bySeverity)) {
      if (items.length === 0) continue;

      blocks.push({
        type: 'section',
        text: {
          type: 'mrkdwn',
          text: `*${severity.toUpperCase()}* (${items.length})`,
        },
      });

      for (const adv of items.slice(0, 10)) {
        const identifiers = adv.cveIds.length > 0 ? adv.cveIds[0] : adv.externalId;
        const refUrl = adv.references[0]?.url || '';
        const linkText = refUrl ? `<${refUrl}|${identifiers}>` : identifiers;

        blocks.push({
          type: 'section',
          text: {
            type: 'mrkdwn',
            text: `• ${linkText} - ${adv.title.substring(0, 100)}${adv.title.length > 100 ? '...' : ''}`,
          },
        });
      }

      if (items.length > 10) {
        blocks.push({
          type: 'section',
          text: {
            type: 'mrkdwn',
            text: `_...and ${items.length - 10} more ${severity} severity items_`,
          },
        });
      }
    }

    blocks.push({
      type: 'divider',
    });

    return blocks;
  }
}
