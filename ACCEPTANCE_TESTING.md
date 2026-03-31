# Acceptance Criteria Testing Checklist

## Setup
- [ ] Docker Compose starts successfully
- [ ] Database migrations run without errors
- [ ] Application logs show "Application started successfully"
- [ ] Health endpoints are accessible

## AC-1: Source Polling
**Given** the application is running with valid configuration  
**When** the polling scheduler executes  
**Then** both configured sources are queried and a fetch run record is stored for each source

**Test Steps:**
```bash
# Check source_fetch_runs table after startup
docker-compose exec postgres psql -U postgres -d advisory_notifier -c "SELECT source_id, status, items_fetched FROM source_fetch_runs ORDER BY started_at DESC LIMIT 5;"
```
- [ ] Verify records exist for both source IDs (1=cisa-kev, 2=osv)
- [ ] Verify status is 'success'
- [ ] Verify items_fetched > 0

## AC-2: Connector Abstraction
**Given** two different advisory sources are implemented  
**When** both connectors are executed  
**Then** both return data through the same internal connector contract

**Test Steps:**
- [ ] Review `src/connectors/base/connector.ts` - interface exists
- [ ] Review `src/connectors/cisa-kev/cisa-kev-connector.ts` - implements interface
- [ ] Review `src/connectors/osv/osv-connector.ts` - implements interface
- [ ] Both return `SourceFetchResult` type
- [ ] Pipeline processes both without source-specific logic

## AC-3: Advisory Normalization
**Given** raw advisory payloads from either source  
**When** normalization completes  
**Then** advisories are stored using the common internal model

**Test Steps:**
```bash
# Check advisories table
docker-compose exec postgres psql -U postgres -d advisory_notifier -c "SELECT id, source_id, external_id, title, severity, exploit_status FROM advisories LIMIT 5;"
```
- [ ] Advisories from both sources exist
- [ ] All required fields are populated (no nulls in required columns)
- [ ] Severity values are normalized ('critical', 'high', 'medium', 'low', 'unknown')

## AC-4: Deduplication by Source ID
**Given** the same source advisory is fetched multiple times  
**When** the pipeline processes it repeatedly  
**Then** only one advisory record exists and duplicate Slack alerts are not sent

**Test Steps:**
1. Note an advisory ID from database
2. Manually trigger source fetch (wait for next poll or restart app)
3. Check database:
```bash
docker-compose exec postgres psql -U postgres -d advisory_notifier -c "SELECT external_id, COUNT(*) FROM advisories GROUP BY external_id HAVING COUNT(*) > 1;"
```
- [ ] No duplicates returned (empty result set)
- [ ] Check notification_events - no duplicate 'instant_alert' for same advisory_id

## AC-5: Deduplication by Identifier
**Given** two advisories from different sources reference the same CVE  
**When** deduplication runs  
**Then** the system handles them according to deduplication strategy

**Test Steps:**
```bash
# Check for CVE appearing in multiple sources
docker-compose exec postgres psql -U postgres -d advisory_notifier -c "
SELECT ai.identifier_value, COUNT(DISTINCT a.source_id) as source_count
FROM advisory_identifiers ai
JOIN advisories a ON a.id = ai.advisory_id
WHERE ai.identifier_type = 'CVE'
GROUP BY ai.identifier_value
HAVING COUNT(DISTINCT a.source_id) > 1;
"
```
- [ ] Review logs for cross-source CVE detection messages
- [ ] Verify notification behavior is logged and intentional

## AC-6: Instant Alert Routing
**Given** a fetched advisory is marked as exploited or classified as critical  
**When** routing is applied  
**Then** the advisory is classified as instant_alert and a Slack message is sent

**Test Steps:**
1. Check CISA KEV advisories (all are exploited):
```bash
docker-compose exec postgres psql -U postgres -d advisory_notifier -c "
SELECT a.id, a.external_id, a.severity, a.exploit_status, ne.notification_type, ne.status
FROM advisories a
LEFT JOIN notification_events ne ON ne.advisory_id = a.id
WHERE a.source_id = 1
LIMIT 5;
"
```
- [ ] CISA KEV items have notification_type='instant_alert'
- [ ] Slack channel shows instant alert messages
- [ ] Messages include severity, exploit status, CVE IDs

## AC-7: Digest Routing
**Given** a fetched advisory is medium or low priority  
**When** routing is applied  
**Then** the advisory is queued for digest

**Test Steps:**
```bash
docker-compose exec postgres psql -U postgres -d advisory_notifier -c "
SELECT severity, COUNT(*) as count
FROM advisories a
WHERE NOT EXISTS (
  SELECT 1 FROM notification_events ne 
  WHERE ne.advisory_id = a.id AND ne.notification_type = 'instant_alert'
)
GROUP BY severity;
"
```
- [ ] Medium/low severity items exist without instant_alert notifications
- [ ] They are candidates for digest

## AC-8: Digest Delivery
**Given** there are digest-eligible advisories  
**When** the digest scheduler runs  
**Then** exactly one digest message is sent and a digest run record is stored

**Test Steps:**
1. Wait for digest schedule time or manually trigger by restarting app at digest time
2. Check digest_runs:
```bash
docker-compose exec postgres psql -U postgres -d advisory_notifier -c "SELECT * FROM digest_runs ORDER BY started_at DESC LIMIT 3;"
```
- [ ] Digest run record exists
- [ ] Status is 'success'
- [ ] items_included > 0
- [ ] Slack shows digest message

## AC-9: No Duplicate Digest Items
**Given** an advisory has been included in a previous digest  
**When** future digest jobs run  
**Then** the same advisory is not re-included

**Test Steps:**
1. After first digest, check notification_events
2. Wait for second digest run
3. Verify:
```bash
docker-compose exec postgres psql -U postgres -d advisory_notifier -c "
SELECT advisory_id, COUNT(*) as notification_count
FROM notification_events
WHERE notification_type = 'digest'
GROUP BY advisory_id
HAVING COUNT(*) > 1;
"
```
- [ ] No advisory has multiple digest notifications (empty result)

## AC-10: Notification Persistence
**Given** any Slack notification is attempted  
**When** the send operation succeeds or fails  
**Then** the result is persisted in notification history

**Test Steps:**
```bash
docker-compose exec postgres psql -U postgres -d advisory_notifier -c "SELECT id, advisory_id, notification_type, status, sent_at, error_message FROM notification_events ORDER BY id DESC LIMIT 10;"
```
- [ ] Successful notifications have status='sent' and sent_at populated
- [ ] Failed notifications have status='failed' and error_message populated
- [ ] slack_message_ref is stored for successful sends

## AC-11: Source Failure Isolation
**Given** one source returns an error  
**When** the polling job runs  
**Then** failure is recorded, app continues, other source is processed

**Test Steps:**
1. Temporarily break one source (modify URL in code or block network)
2. Wait for poll cycle or restart
3. Check:
```bash
docker-compose exec postgres psql -U postgres -d advisory_notifier -c "SELECT s.name, sfr.status, sfr.error_message FROM source_fetch_runs sfr JOIN sources s ON s.id = sfr.source_id ORDER BY sfr.started_at DESC LIMIT 4;"
```
- [ ] Failed source has error_message
- [ ] Other source still shows success
- [ ] App remains running (health check still returns 200)

## AC-12: Health Endpoints
**Given** the app is running  
**When** health endpoints are called  
**Then** they return appropriate status

**Test Steps:**
```bash
# Liveness
curl http://localhost:3000/health/live

# Readiness
curl http://localhost:3000/health/ready
```
- [ ] /health/live returns 200 with {"status": "ok"}
- [ ] /health/ready returns 200 with database: "healthy"
- [ ] /health/ready includes sources status array

## AC-13: Dockerized Local Run
**Given** a developer follows the README  
**When** they run Docker Compose  
**Then** app and PostgreSQL start successfully

**Test Steps:**
```bash
docker-compose up --build
```
- [ ] No build errors
- [ ] PostgreSQL starts and passes health check
- [ ] App connects to database
- [ ] Logs show successful initialization
- [ ] Initial source fetch completes

## AC-14: Externalized Configuration
**Given** a fresh environment  
**When** the app starts  
**Then** all secrets are loaded from environment variables

**Test Steps:**
- [ ] Review all source files - no hardcoded tokens or passwords
- [ ] .env.example contains all required variables
- [ ] docker-compose.yml uses ${VARIABLE} syntax for secrets
- [ ] App fails gracefully if required env vars missing

## AC-15: Logging
**Given** polling, normalization, routing, and delivery occur  
**When** reviewing logs  
**Then** logs clearly show actions and failures

**Test Steps:**
```bash
docker-compose logs app | grep -E "(Fetching|normalized|routed|alert sent|failed)"
```
- [ ] Source fetch logged with source name
- [ ] Advisory processing shows external_id
- [ ] Routing decisions logged with routing class
- [ ] Slack delivery success/failure logged
- [ ] Errors include stack traces in dev mode

## AC-16: Minimal Test Coverage
**Given** the codebase is delivered  
**When** automated tests are run  
**Then** core paths have test coverage

**Test Steps:**
```bash
npm install
npm test
```
- [ ] Normalization tests pass (both CISA and OSV)
- [ ] Scoring tests pass
- [ ] Routing tests pass
- [ ] Slack notification test passes
- [ ] Utils tests pass
- [ ] All tests complete without errors

## Summary

Total Acceptance Criteria: 16  
Passed: _____ / 16  
Failed: _____ / 16  

**Status:** [ ] Ready for Production  [ ] Needs Fixes

**Notes:**
_Add any observations or issues found during testing_
