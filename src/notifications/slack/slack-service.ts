import { WebClient } from '@slack/web-api';
import { config } from '../../config';
import { NormalizedAdvisory } from '../../shared';
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

  async sendInstantAlert(advisory: NormalizedAdvisory): Promise<SlackMessageResult> {
    try {
      logger.info({ externalId: advisory.externalId }, 'Sending instant alert');

      const blocks = this.buildInstantAlertBlocks(advisory);

      const response = await this.client.chat.postMessage({
        channel: config.slack.channelId,
        text: `🚨 Security Advisory: ${advisory.title}`,
        blocks,
      });

      if (response.ok && response.ts) {
        logger.info(
          { externalId: advisory.externalId, messageTs: response.ts },
          'Instant alert sent successfully'
        );

        return {
          success: true,
          messageRef: response.ts,
        };
      } else {
        const errorMessage = `Slack API returned not ok: ${response.error}`;
        logger.error({ externalId: advisory.externalId, error: response.error }, 'Slack message failed');
        
        return {
          success: false,
          errorMessage,
        };
      }
    } catch (error: any) {
      const errorMessage = error?.message || String(error);
      logger.error({ error, externalId: advisory.externalId }, 'Failed to send instant alert');
      
      return {
        success: false,
        errorMessage,
      };
    }
  }

  async sendDigest(advisories: NormalizedAdvisory[]): Promise<SlackMessageResult> {
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

  private buildInstantAlertBlocks(advisory: NormalizedAdvisory): any[] {
    const severityEmoji: Record<string, string> = {
      critical: '🔴',
      high: '🟠',
      medium: '🟡',
      low: '🟢',
      unknown: '⚪',
    };
    const emoji = severityEmoji[advisory.severity] ?? '⚪';
    const severityLabel = `${emoji} ${advisory.severity.toUpperCase()}`;

    const exploited = advisory.exploitStatus === 'exploited';

    // Identifiers: prefer CVE IDs, fallback to externalId
    const identifiers = advisory.cveIds.length > 0
      ? advisory.cveIds.join(', ')
      : advisory.externalId;

    // Source label: "NVD", "OSV - npm", "github-advisory"
    const rawPayload = advisory.rawPayload || {};
    const ecosystem: string | undefined = rawPayload._ecosystem;
    const sourceLabel = advisory.source === 'osv' && ecosystem
      ? `OSV - ${ecosystem}`
      : advisory.source.toUpperCase().replace(/-/g, ' ');

    // Dates
    const publishedStr = advisory.publishedAt
      ? advisory.publishedAt.toISOString().split('T')[0]
      : '—';
    const modifiedStr = advisory.updatedAt
      ? advisory.updatedAt.toISOString().split('T')[0]
      : null;

    // Header line
    const headerText = exploited
      ? `🚨 ${severityLabel}  |  💥 EXPLOITED`
      : `🚨 ${severityLabel}`;

    // Primary link
    const firstRef = advisory.references[0];
    const titleText = firstRef
      ? `*<${firstRef.url}|${advisory.title}>*`
      : `*${advisory.title}*`;

    const blocks: any[] = [
      {
        type: 'header',
        text: { type: 'plain_text', text: headerText, emoji: true },
      },
      {
        type: 'section',
        text: { type: 'mrkdwn', text: titleText },
      },
      {
        type: 'section',
        fields: [
          { type: 'mrkdwn', text: `*🔍 Identifiers*\n\`${identifiers}\`` },
          { type: 'mrkdwn', text: `*📡 Source*\n${sourceLabel}` },
          { type: 'mrkdwn', text: `*📅 Published*\n${publishedStr}` },
          { type: 'mrkdwn', text: modifiedStr
              ? `*🔄 Last Modified*\n${modifiedStr}`
              : `*🏷 Vendor*\n${advisory.vendor || '—'}` },
        ],
      },
    ];

    if (advisory.summary) {
      blocks.push({
        type: 'section',
        text: {
          type: 'mrkdwn',
          text: `*📝 Summary*\n${advisory.summary.substring(0, 600)}${advisory.summary.length > 600 ? '...' : ''}`,
        },
      });
    }

    // Up to 3 references as buttons
    const refLinks = advisory.references.slice(0, 3);
    if (refLinks.length > 0) {
      blocks.push({
        type: 'actions',
        elements: refLinks.map(ref => ({
          type: 'button',
          text: { type: 'plain_text', text: ref.label || 'View Advisory', emoji: true },
          url: ref.url,
        })),
      });
    }

    blocks.push({ type: 'divider' });

    return blocks;
  }

  private buildDigestBlocks(advisories: NormalizedAdvisory[]): any[] {
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
    const bySeverity: Record<string, NormalizedAdvisory[]> = {
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
