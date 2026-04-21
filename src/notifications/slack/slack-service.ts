import { WebClient } from '@slack/web-api';
import { NormalizedAdvisory } from '../../shared';
import logger from '../../logging';

export interface SlackMessageResult {
  success: boolean;
  messageRef?: string;
  errorMessage?: string;
}

export class SlackService {
  private client: WebClient;
  private channelId: string;

  constructor(botToken: string, channelId: string) {
    this.client = new WebClient(botToken);
    this.channelId = channelId;
  }

  async sendInstantAlert(advisory: NormalizedAdvisory): Promise<SlackMessageResult> {
    try {
      logger.info({ externalId: advisory.externalId }, 'Sending instant alert');

      const blocks = this.buildInstantAlertBlocks(advisory);

      const response = await this.client.chat.postMessage({
        channel: this.channelId,
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

  async sendThreadedBatch(advisories: NormalizedAdvisory[]): Promise<SlackMessageResult> {
    try {
      if (advisories.length === 0) {
        return { success: true };
      }

      logger.info({ count: advisories.length }, 'Sending threaded batch');

      const criticalCount = advisories.filter(a => a.severity === 'critical').length;
      const highCount = advisories.filter(a => a.severity === 'high').length;
      const severityEmoji: Record<string, string> = { critical: '🔴', high: '🟠', medium: '🟡', low: '🟢', unknown: '⚪' };

      const severitySummary = [
        criticalCount > 0 ? `${criticalCount} critical` : '',
        highCount > 0 ? `${highCount} high` : '',
      ].filter(Boolean).join(', ') || `${advisories.length} findings`;

      // Build parent summary message
      const summaryLines = advisories.map(a => {
        const emoji = severityEmoji[a.severity] ?? '⚪';
        const id = a.cveIds[0] ?? a.externalId;
        const refUrl = a.references[0]?.url;
        const idText = refUrl ? `<${refUrl}|${id}>` : `\`${id}\``;
        const desc = (a.summary || a.title).replace(/\n/g, ' ').substring(0, 80);
        return `${emoji} *${idText}* — ${desc}`;
      });

      const parentBlocks: any[] = [
        {
          type: 'header',
          text: {
            type: 'plain_text',
            text: `🚨 ${advisories.length} new security finding${advisories.length === 1 ? '' : 's'} (${severitySummary}) — expand for details`,
            emoji: true,
          },
        },
      ];

      // 15 lines per section to stay under 3000 char limit
      for (let i = 0; i < summaryLines.length; i += 15) {
        parentBlocks.push({
          type: 'section',
          text: { type: 'mrkdwn', text: summaryLines.slice(i, i + 15).join('\n') },
        });
      }

      const parentResponse = await this.client.chat.postMessage({
        channel: this.channelId,
        text: `🚨 ${advisories.length} new security findings (${severitySummary})`,
        blocks: parentBlocks,
        unfurl_links: false,
        unfurl_media: false,
      });

      if (!parentResponse.ok || !parentResponse.ts) {
        return { success: false, errorMessage: `Parent message failed: ${parentResponse.error}` };
      }

      const threadTs = parentResponse.ts;
      logger.info({ threadTs, count: advisories.length }, 'Parent message sent, posting thread replies');

      // Post each finding as a thread reply
      for (const advisory of advisories) {
        try {
          const blocks = this.buildInstantAlertBlocks(advisory);
          await this.client.chat.postMessage({
            channel: this.channelId,
            thread_ts: threadTs,
            text: `🚨 ${advisory.title}`,
            blocks,
          });
        } catch (err) {
          logger.warn({ err, externalId: advisory.externalId }, 'Failed to post thread reply, continuing');
        }
      }

      logger.info({ threadTs, count: advisories.length }, 'Threaded batch complete');
      return { success: true, messageRef: threadTs };
    } catch (error: any) {
      const errorMessage = error?.message || String(error);
      logger.error({ error }, 'Failed to send threaded batch');
      return { success: false, errorMessage };
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
}
