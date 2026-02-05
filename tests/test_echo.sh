#!/bin/bash
# SPDX-FileCopyrightText: (C) 2026 Dell Technologies
# SPDX-License-Identifier: Apache 2.0
# Author: Brad Goodman

# Test the echo command that should be called by voucher upload
serial="TEST-SN-123456"
model="TestModel"
guid="ABC123DEF456"
voucherfile="/tmp/test_voucher.cbor"

echo "Testing echo command with variables:"
echo "Serial: $serial"
echo "Model: $model"
echo "GUID: $guid"
echo "Voucher File: $voucherfile"

# Test the exact command from our config
command="echo 'Voucher uploaded: serial=$serial model=$model guid=$guid voucherfile=$voucherfile'"
echo "Command: $command"
echo "Output:"
eval $command
