import { SlackService } from '../../src/notifications/slack/slack-service';
import { StoredAdvisory } from '../../src/shared/types';

// Mock Slack client
jest.mock('@slack/web-api', () => {
  return {
    WebClient: jest.fn().mockImplementation(() => ({
      chat: {
        postMessage: jest.fn().mockResolvedValue({
          ok: true,
          ts: '1234567890.123456',
        }),
      },
    })),
  };
});

// Mock config
jest.mock('../../src/config', () => ({
  config: {
    slack: {
      botToken: 'xoxb-test-token',
      channelId: 'C01234567890',
    },
  },
}));

describe('SlackService', () => {
  let slackService: SlackService;

  beforeEach(() => {
    slackService = new SlackService();
  });

  const mockAdvisory: StoredAdvisory = {
    id: 1,
    sourceId: 1,
    externalId: 'CVE-2024-1234',
    source: 'cisa-kev',
    title: 'Test Vulnerability',
    summary: 'This is a test vulnerability',
    severity: 'high',
    vendor: 'TestVendor',
    publishedAt: new Date('2024-01-15'),
    updatedAt: null,
    cveIds: ['CVE-2024-1234'],
    references: [{ url: 'https://nvd.nist.gov/vuln/detail/CVE-2024-1234', label: 'NVD' }],
    tags: [],
    exploitStatus: 'exploited',
    status: 'active',
    rawPayload: {},
    rawHash: 'hash123',
    createdAt: new Date(),
    modifiedAt: new Date(),
  };

  test('should send instant alert successfully', async () => {
    const result = await slackService.sendInstantAlert(mockAdvisory);

    expect(result.success).toBe(true);
    expect(result.messageRef).toBeDefined();
  });

  test('should send digest successfully', async () => {
    const result = await slackService.sendDigest([mockAdvisory]);

    expect(result.success).toBe(true);
    expect(result.messageRef).toBeDefined();
  });

  test('should handle empty digest gracefully', async () => {
    const result = await slackService.sendDigest([]);

    expect(result.success).toBe(true);
  });
});
