#!/bin/bash
# SPDX-FileCopyrightText: (C) 2026 Dell Technologies
# SPDX-License-Identifier: Apache 2.0
# Author: Brad Goodman

# Example OVEExtra data script
# Usage: ./test_ove_extra_data.sh <serial> <model>

SERIAL="$1"
MODEL="$2"

# Example: Return JSON with customer and order number
cat <<EOF
{
  "customer": "ACME Corp",
  "order_number": "ORD-$(date +%s)",
  "serial": "$SERIAL",
  "model": "$MODEL",
  "manufacturing_date": "$(date -I)",
  "facility": "Factory-01",
  "test_data": {
    "batch_id": "BATCH-123",
    "quality_score": 0.95,
    "inspected_by": "Inspector-001"
  }
}
EOF
