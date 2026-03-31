#!/bin/bash

echo "=== AdvisoryWire Manual Test ==="

# Step 1: Insert test advisory (correct schema - no cve_id column, uses raw_hash)
echo "1. Inserting test advisory..."
ADVISORY_ID=$(docker exec advisorywire-db psql \
  -U advisorywire \
  -d advisorywire_db \
  -t -c "INSERT INTO advisories (
    source_id, external_id, title, summary,
    severity, exploit_status, status,
    published_at, raw_hash, raw_payload
  ) VALUES (
    1,
    'test-' || extract(epoch from now())::text,
    'TEST CRITICAL ADVISORY - CVE-2024-9999',
    'Manual test for Slack notifications',
    'critical',
    'exploited',
    'active',
    NOW(),
    md5('test-' || extract(epoch from now())::text),
    '{\"manual\": true, \"cve\": \"CVE-2024-9999\"}'::jsonb
  ) RETURNING id;" | xargs)

echo "   Advisory ID: $ADVISORY_ID"

if [ -z "$ADVISORY_ID" ]; then
  echo "ERROR: Failed to insert advisory!"
  exit 1
fi

# Step 2: Insert CVE identifier
echo "2. Adding CVE identifier..."
docker exec advisorywire-db psql \
  -U advisorywire \
  -d advisorywire_db \
  -c "INSERT INTO advisory_identifiers (advisory_id, identifier_type, identifier_value)
      VALUES ($ADVISORY_ID, 'CVE', 'CVE-2024-9999');"

# Step 3: Insert notification event
echo "3. Creating notification event..."
docker exec advisorywire-db psql \
  -U advisorywire \
  -d advisorywire_db \
  -c "INSERT INTO notification_events (advisory_id, notification_type, channel, status, sent_at)
      VALUES ($ADVISORY_ID, 'instant_alert', 'slack', 'pending', NOW());"

echo ""
echo "Done! Now run:"
echo "   docker compose logs -f app --tail 50"
echo ""
echo "Then check your Slack channel for the alert!"
