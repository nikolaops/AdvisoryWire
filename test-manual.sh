#!/bin/bash

echo "=== AdvisoryWire Manual Test ==="

# Step 1: Insert test advisory
echo "1. Inserting test advisory..."
ADVISORY_ID=$(docker exec advisorywire-db psql \
  -U advisorywire \
  -d advisorywire_db \
  -t -c "INSERT INTO advisories (
    source_id, external_id, cve_id, title, description,
    severity, exploit_status, first_seen, last_seen, source_data
  ) VALUES (
    1,
    'test-' || extract(epoch from now())::text,
    'CVE-2024-9999',
    'TEST CRITICAL ADVISORY',
    'Manual test for Slack notifications',
    'critical',
    'exploited',
    NOW(), NOW(),
    '{\"manual\": true}'::jsonb
  ) RETURNING id;" | xargs)

echo "   Advisory ID: $ADVISORY_ID"

# Step 2: Insert notification event
echo "2. Creating notification event..."
docker exec advisorywire-db psql \
  -U advisorywire \
  -d advisorywire_db \
  -c "INSERT INTO notification_events (advisory_id, channel, status, created_at)
      VALUES ($ADVISORY_ID, 'slack_instant', 'pending', NOW());"

echo "3. Done! Check logs:"
echo "   docker compose logs -f app --tail 50"
echo ""
echo "4. Check your Slack channel for the alert!"
