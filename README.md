# AdvisoryWire

Security advisory aggregator that pulls from OSV, GitHub Advisory, and NVD — deduplicates, scores, and sends Slack alerts.

> **Branch:** `lambda-aws` — AWS Lambda + DynamoDB deployment  
> For Docker Compose / VPS deployment see the `main` branch.

## How It Works

Three EventBridge rules trigger the Lambda every 6 hours (staggered by 20 min):

```
OSV  :00  →  GitHub Advisory  :20  →  NVD  :40
                    ↓
              Normalize & score
                    ↓
          DynamoDB dedup (48h TTL)
                    ↓
     critical/exploited → instant Slack alert
     medium/low         → skipped (no digest in Lambda mode)
```

Cross-source dedup: if OSV already sent CVE-2024-1234, NVD won't re-alert on the same CVE.

## Prerequisites

- AWS account with ECR, Lambda, DynamoDB, EventBridge, Secrets Manager
- Slack Bot Token (`chat:write` scope) and Channel ID
- Terraform (for infrastructure provisioning — see `codetiq-github/terraform/finansije`)

## Deploy

### 1. Provision infrastructure

Infrastructure is managed via Terraform in `codetiq-github/terraform/finansije`. Apply in two steps — first ECR, then everything else — so the image can be pushed before Lambda is created.

### 2. Build and push image

```bash
ECR=120569631504.dkr.ecr.eu-west-1.amazonaws.com/dev-advisorywire

aws ecr get-login-password --region eu-west-1 --profile finansije \
  | docker login --username AWS --password-stdin 120569631504.dkr.ecr.eu-west-1.amazonaws.com

docker build --platform linux/amd64 --provenance=false \
  -f Dockerfile.lambda \
  -t $ECR:latest .

docker push $ECR:latest
```

### 3. Apply remaining infrastructure

Apply the remaining Terraform resources (Lambda, IAM, DynamoDB, EventBridge).

### 4. Set Slack secrets

```bash
aws secretsmanager put-secret-value \
  --region eu-west-1 \
  --profile finansije \
  --secret-id advisorywire \
  --secret-string '{"SLACK_BOT_TOKEN":"xoxb-...","SLACK_CHANNEL_ID":"C05EAL8MJSE"}'
```

### Update image (after code changes)

```bash
docker build --platform linux/amd64 --provenance=false -f Dockerfile.lambda -t $ECR:latest . \
  && docker push $ECR:latest

aws lambda update-function-code \
  --function-name finansije-advisorywire \
  --image-uri $ECR:latest \
  --region eu-west-1 \
  --profile finansije
```

## Configuration

All configuration is set as Lambda environment variables (managed via Terraform `advisorywire.tf`).

| Variable | Default | Description |
|---|---|---|
| `DYNAMODB_TABLE` | `advisorywire` | DynamoDB table name |
| `ADVISORYWIRE_SECRET_NAME` | `advisorywire` | Secrets Manager secret name |
| `NODE_ENV` | `production` | Node environment |
| `LOG_LEVEL` | `info` | Log level (`debug`, `info`, `warn`, `error`) |
| `INSTANT_ALERT_SEVERITIES` | `critical,high` | Severity levels that trigger instant alert |
| `INSTANT_ALERT_IF_EXPLOITED` | `true` | Alert immediately if exploit status is `exploited` |
| `DIGEST_SEVERITIES` | `medium,low` | Severities routed to digest (currently not sent in Lambda mode) |
| `NVD_ECOSYSTEMS` | *(empty = all)* | Comma-separated CPE keywords to filter NVD results |
| `OSV_ECOSYSTEMS` | *(see below)* | Comma-separated OSV ecosystem names to monitor |

### Monitored sources

**OSV** (default ecosystems, overridable via `OSV_ECOSYSTEMS`):
```
Debian, Ubuntu, Alpine, Rocky Linux, AlmaLinux,
npm, PyPI, Go, NuGet, Packagist, GitHub Actions, VSCode
```

**GitHub Advisory** — all advisories from the GitHub Advisory Database

**NVD** (filtered via `NVD_ECOSYSTEMS`):
```
microsoft:windows, apple:macos, apple:mac_os_x
```
NVD filter matches against CPE configuration strings and CVE description text.
Empty `NVD_ECOSYSTEMS` = no filter (fetches all CVEs).

### GitHub Advisory rate limits

Without a token: 60 requests/hour. With `GITHUB_TOKEN`: 5,000 requests/hour.  
Token is optional — stored in Secrets Manager alongside Slack credentials if needed:
```json
{"SLACK_BOT_TOKEN":"xoxb-...","SLACK_CHANNEL_ID":"...","GITHUB_TOKEN":"ghp_..."}
```

### NVD API rate limits

Without key: 5 requests / 30s. With `NVD_API_KEY`: 50 requests / 30s.  
Free key: https://nvd.nist.gov/developers/request-an-api-key  
Add to Secrets Manager:
```json
{"SLACK_BOT_TOKEN":"...","SLACK_CHANNEL_ID":"...","NVD_API_KEY":"..."}
```

## Local development

```bash
npm install
npm test
npm run build
```

The Lambda handler entry point is `src/lambda/handler.ts`. It can be invoked locally with:
```bash
node -e "require('./dist/lambda/handler').handler({ source: 'osv' })"
```


An MVP application that aggregates security advisories from trusted public sources, normalizes them into a common model, deduplicates them, scores and routes them using configurable rules, and sends notifications to Slack.

## Important Note

**This is NOT a vulnerability scanner.** This application does not:
- Scan source code repositories
- Analyze lockfiles or SBOMs
- Scan client systems or cloud environments
- Crawl GitHub repositories

This is a **centralized advisory ingestion and notification engine** that pulls from public advisory feeds.

## Features

✅ **Multi-source ingestion**
- CISA Known Exploited Vulnerabilities (KEV)
- OSV (Open Source Vulnerabilities)
- Extensible connector architecture

✅ **Normalization & Deduplication**
- Common internal advisory model
- Deduplication by source ID, CVE, and content hash
- Update detection for modified advisories

✅ **Smart Routing**
- Configurable scoring based on severity, exploit status, and recency
- Instant alerts for critical/exploited vulnerabilities
- Daily digest for medium/low priority items

✅ **Slack Integration**
- Rich formatted instant alerts
- Daily digest summaries
- No duplicate notifications

✅ **Production-Ready**
- PostgreSQL persistence
- Scheduled polling with cron
- Health endpoints for monitoring
- Structured JSON logging
- Docker support

## Architecture

```
┌─────────────┐     ┌─────────────┐
│  CISA KEV   │     │     OSV     │
└──────┬──────┘     └──────┬──────┘
       │                   │
       └─────────┬─────────┘
                 │
         ┌───────▼────────┐
         │   Connectors   │
         └───────┬────────┘
                 │
         ┌───────▼────────┐
         │ Normalization  │
         └───────┬────────┘
                 │
         ┌───────▼────────┐
         │ Deduplication  │
         └───────┬────────┘
                 │
         ┌───────▼────────┐
         │ Scoring/Routing│
         └───────┬────────┘
                 │
         ┌───────▼────────┐
         │  PostgreSQL    │
         └───────┬────────┘
                 │
         ┌───────▼────────┐
         │     Slack      │
         └────────────────┘
```

## Prerequisites

- Docker & Docker Compose
- Slack Bot Token with `chat:write` permission
- Slack Channel ID

## Quick Start

### 1. Clone and Setup

```bash
cd E:\GIT\CVEscrapper
cp .env.example .env
```

### 2. Configure Slack

Edit `.env` and add your Slack credentials:

```env
SLACK_BOT_TOKEN=xoxb-your-actual-bot-token
SLACK_CHANNEL_ID=C01234567890
```

**Getting Slack credentials:**
1. Go to https://api.slack.com/apps
2. Create a new app or select existing
3. Add `chat:write` bot token scope
4. Install app to your workspace
5. Copy Bot User OAuth Token
6. Invite bot to your channel and copy Channel ID

### 3. Start the Application

```bash
docker-compose up --build
```

The application will:
- Start PostgreSQL database
- Run database migrations
- Start the API server on port 3000
- Begin scheduled polling of sources
- Send instant alerts for high-priority advisories
- Send daily digest at 9:00 AM UTC

### 4. Verify it's Running

Check health endpoint:
```bash
curl http://localhost:3000/health/ready
```

Expected response:
```json
{
  "status": "ready",
  "database": "healthy",
  "sources": [...],
  "timestamp": "2024-01-15T10:30:00.000Z"
}
```

## Configuration

All configuration is done via environment variables in `.env`:

### Database
```env
DATABASE_HOST=postgres
DATABASE_PORT=5432
DATABASE_NAME=advisory_notifier
DATABASE_USER=postgres
DATABASE_PASSWORD=your_secure_password
```

### Slack
```env
SLACK_BOT_TOKEN=xoxb-your-bot-token
SLACK_CHANNEL_ID=C01234567890
```

### Polling Schedule (Cron Format)
```env
CISA_KEV_POLL_INTERVAL=0 */6 * * *    # Every 6 hours
OSV_POLL_INTERVAL=0 */6 * * *         # Every 6 hours
```

### Digest Schedule
```env
DIGEST_SCHEDULE=0 9 * * *             # 9:00 AM daily
DIGEST_TIMEZONE=UTC
```

### Routing Rules
```env
INSTANT_ALERT_SEVERITIES=critical,high
INSTANT_ALERT_IF_EXPLOITED=true
DIGEST_SEVERITIES=medium,low
```

## Development

### Local Development Setup

```bash
# Install dependencies
npm install

# Copy environment file
cp .env.example .env

# Edit .env with your configuration

# Start PostgreSQL
docker-compose up postgres -d

# Run migrations
npm run migrate

# Start in development mode
npm run dev
```

### Run Tests

```bash
npm test
```

### Build

```bash
npm run build
npm start
```

## API Endpoints

### Health Endpoints

**Liveness Probe**
```
GET /health/live
```
Returns 200 if process is alive.

**Readiness Probe**
```
GET /health/ready
```
Returns 200 if app is ready (DB connected, sources configured).

### Root Endpoint
```
GET /
```
Returns basic app info.

## Database Schema

### Core Tables

- **sources**: Advisory source configurations
- **source_fetch_runs**: History of polling attempts
- **advisories**: Normalized advisory records
- **advisory_identifiers**: CVE and source-native IDs
- **advisory_references**: External reference links
- **notification_events**: Slack notification history
- **digest_runs**: Daily digest execution history

## Notification Behavior

### Instant Alerts

Sent immediately when:
- Advisory has `exploit_status = exploited` (e.g., CISA KEV items)
- Advisory severity is `critical` or `high`

Format:
- Rich Slack blocks with severity indicators
- CVE identifiers
- Summary and references
- Published date

### Daily Digest

Sent at scheduled time (default 9:00 AM UTC) with:
- All `medium` and `low` severity advisories from last 24 hours
- Grouped by severity
- Compact format with links

### Deduplication Rules

The system prevents duplicate notifications by:
1. Checking `source_id` + `external_id`
2. Checking CVE identifiers across sources
3. Computing content hash for change detection
4. Tracking all notification events in database

## Troubleshooting

### Application won't start

Check Docker logs:
```bash
docker-compose logs app
```

Common issues:
- Missing Slack credentials in `.env`
- Database connection failure
- Port 3000 already in use

### No advisories appearing

Check:
1. Source fetch runs: Query `source_fetch_runs` table
2. Application logs for fetch errors
3. Network connectivity to advisory sources

### Slack notifications not sending

Verify:
1. `SLACK_BOT_TOKEN` is correct
2. Bot is invited to the channel
3. `SLACK_CHANNEL_ID` matches your target channel
4. Check `notification_events` table for error messages

### Database connection issues

```bash
# Check if PostgreSQL is running
docker-compose ps

# Restart database
docker-compose restart postgres

# View database logs
docker-compose logs postgres
```

## Project Structure

```
src/
├── app/                 # Application entry point
├── config/              # Configuration management
├── connectors/          # Source connectors
│   ├── base/           # Base connector interface
│   ├── cisa-kev/       # CISA KEV connector
│   └── osv/            # OSV connector
├── pipeline/           # Pipeline orchestration
├── normalization/      # Advisory normalizers
├── dedup/              # Deduplication service
├── scoring/            # Scoring logic
├── routing/            # Routing decisions
├── notifications/      # Notification services
│   └── slack/         # Slack integration
├── persistence/        # Database layer
│   ├── repositories/  # Data access
│   └── migrations/    # SQL migrations
├── scheduler/          # Cron job scheduler
├── api/               # HTTP API
│   └── health/       # Health endpoints
├── logging/           # Logging configuration
└── shared/            # Shared types and utilities
```

## Adding New Sources

To add a new advisory source:

1. **Create connector** in `src/connectors/new-source/`
   - Implement `SourceConnector` interface
   - Add to `getConnectors()` in `src/connectors/index.ts`

2. **Create normalizer** in `src/normalization/normalizers.ts`
   - Implement `Normalizer` interface
   - Add to `getNormalizerForSource()` factory

3. **Add source record** in migration or manually insert:
   ```sql
   INSERT INTO sources (name, type, enabled) VALUES ('new-source', 'new_source_type', true);
   ```

4. **Configure polling** in `.env`:
   ```env
   NEW_SOURCE_POLL_INTERVAL=0 */6 * * *
   ```

5. **Update scheduler** in `src/scheduler/index.ts` to add new scheduled job

## Extending the MVP

Future enhancements (currently out of scope):
- Additional notification channels (Teams, Email)
- Interactive Slack buttons
- Web dashboard
- Multi-tenant support
- Machine learning relevance scoring
- Jira integration
- Repository scanning (requires different architecture)

## License

MIT

## Support

For issues or questions, please check the logs and health endpoints first. The application is designed to be self-documenting through structured logs.
