# Security Advisory Notifier - Quick Start Guide

## Prerequisites
- Docker Desktop installed and running
- Slack workspace with admin access
- 10 minutes

## Setup Steps

### 1. Get Slack Credentials

1. Go to https://api.slack.com/apps
2. Click "Create New App" → "From scratch"
3. Name it "Security Advisory Bot", select your workspace
4. Go to "OAuth & Permissions"
5. Under "Scopes" → "Bot Token Scopes", add `chat:write`
6. Click "Install to Workspace"
7. Copy the "Bot User OAuth Token" (starts with `xoxb-`)
8. Invite the bot to your desired channel: `/invite @Security Advisory Bot`
9. Copy the Channel ID (right-click channel → View channel details)

### 2. Configure Application

```bash
cd E:\GIT\CVEscrapper
cp .env.example .env
```

Edit `.env` and set:
```env
SLACK_BOT_TOKEN=xoxb-your-actual-token-here
SLACK_CHANNEL_ID=C01234567890
DATABASE_PASSWORD=choose_a_secure_password
```

### 3. Start Application

```bash
docker-compose up --build
```

Wait for:
```
✓ Database migrations completed
✓ API server started on port 3000
✓ Scheduler started
✓ Initial source fetch completed
```

### 4. Verify

Open another terminal and check:

```bash
# Health check
curl http://localhost:3000/health/ready

# Check your Slack channel for alerts
```

### 5. Monitor Logs

```bash
# View real-time logs
docker-compose logs -f app

# View database logs
docker-compose logs -f postgres
```

## What Happens Next

- **Immediate**: Initial fetch from CISA KEV and OSV sources
- **Every 6 hours**: Automatic polling for new advisories
- **9:00 AM UTC daily**: Digest message with medium/low priority items
- **Real-time**: Instant alerts for critical/exploited vulnerabilities

## Stopping the Application

```bash
docker-compose down
```

To remove data as well:
```bash
docker-compose down -v
```

## Troubleshooting

**No Slack messages appearing:**
- Verify bot is invited to channel
- Check app logs: `docker-compose logs app`
- Verify credentials in `.env`

**Database connection errors:**
- Ensure ports aren't blocked
- Check `docker-compose ps` shows postgres as healthy

**Need to reset everything:**
```bash
docker-compose down -v
docker-compose up --build
```

## Next Steps

See [README.md](README.md) for:
- Detailed configuration options
- Adding new advisory sources
- API documentation
- Development guide
