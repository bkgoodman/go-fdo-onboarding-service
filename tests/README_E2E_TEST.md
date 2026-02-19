# FDO End-to-End Integration Test

Single source of truth for the automated integration test located at `tests/test_e2e_integration.sh`. Run it from the repo root:

```bash
cd /var/bkgdata/go-fdo-onboarding-service
./tests/test_e2e_integration.sh
```

The script is fully automated and self-describing. It builds all three components (Manufacturing Station, Onboarding Service, Device Client), initializes their databases/keys, launches services, and drives the DI → TO2 flow while capturing every artifact under `/tmp/fdo_e2e_test/`.

---

## Components & Roles

| Component | Repository | Role | Port |
| --- | --- | --- | --- |
| Manufacturing Station | `/home/windsurf/go-fdo-di` | DI server, voucher creation & push | 8081 |
| Onboarding Service | `/var/bkgdata/go-fdo-onboarding-service` | TO2 server, voucher receiver, FSIM delivery | 8082 |
| Device/Endpoint Client | `/var/bkgdata/go-fdo-endpoint` | Simulated IoT device performing DI + TO2 | n/a |

Key behaviors enforced by the script:

1. Credential reuse enabled on the onboarding service (`voucher_management.reuse_credential: true`).
2. Voucher push authentication token set to `test-integration-token` on both ends.
3. FSIM sysconfig injects `hostname=E2Etest` and is validated in the TO2 log.
4. TO0/TO1 are skipped intentionally; the client performs direct TO2 against `http://127.0.0.1:8082`.

---

## Phase Breakdown (mirrors script sections)

1. **Environment Setup** – clears ports 8081/8082, recreates `/tmp/fdo_e2e_test`, and enumerates artifact paths.
2. **Build Components** – builds each Go binary if missing or stale.
3. **Init Onboarding Service** – generates `onboarding_config.yaml`, runs `-init-only`, extracts SECP384R1 owner key, and stores it at `/tmp/fdo_e2e_test/owner_public_key.pem`.
4. **Init Manufacturing Station** – generates `mfg_config.yaml`, runs `-init-only`, and wires in the extracted owner key plus voucher push settings.
5. **Device Config** – writes `device_config.cfg` pointing DI to port 8081 and TO2 to port 8082, storing credentials at `/tmp/fdo_e2e_test/cred.bin`.
6. **Start Services** – launches both servers in the background, waits for readiness, and tails logs on failure.
7. **Device Initialization (DI)** – deletes previous creds, runs DI from the test directory (to avoid cross-device rename issues), confirms voucher creation, and verifies push delivery.
8. **Transfer Ownership (TO2)** – runs direct TO2, confirms credential reuse messaging, and checks for `hostname=E2Etest` in the device log.
9. **Verification & Summary** – greps all logs for success markers and prints artifact locations plus future TODOs.

---

## Artifact Layout (`/tmp/fdo_e2e_test`)

| Path | Description |
| --- | --- |
| `manufacturing.db` | Manufacturing Station SQLite database |
| `mfg_vouchers/*.fdoov` | Locally saved vouchers created during DI |
| `manufacturing.log` | Manufacturing Station runtime log |
| `mfg_config.yaml` | Generated Manufacturing Station config |
| `onboarding.db` | Onboarding Service SQLite database |
| `onboarding_vouchers/*.fdoov` | Vouchers received via HTTP push |
| `onboarding.log` | Onboarding Service runtime log |
| `onboarding_config.yaml` | Generated Onboarding Service config |
| `configs/` | Device/group config output directory referenced by device_storage |
| `cred.bin` | Device credential blob (created during DI) |
| `device_di.log` / `device_to2.log` | Endpoint client logs for each phase |
| `device_config.cfg` | Endpoint client configuration |
| `owner_public_key.pem` | Extracted PEM used for owner signover |

View or tail logs:

```bash
tail -f /tmp/fdo_e2e_test/manufacturing.log
tail -f /tmp/fdo_e2e_test/onboarding.log
cat /tmp/fdo_e2e_test/device_di.log
cat /tmp/fdo_e2e_test/device_to2.log
```

Inspect vouchers or databases:

```bash
ls -lh /tmp/fdo_e2e_test/mfg_vouchers/
ls -lh /tmp/fdo_e2e_test/onboarding_vouchers/
sqlite3 /tmp/fdo_e2e_test/manufacturing.db
sqlite3 /tmp/fdo_e2e_test/onboarding.db
```

---

## Manual Component Control

Useful for debugging individual phases:

```bash
# Manufacturing Station
cd /home/windsurf/go-fdo-di
./fdo-manufacturing-station -config /tmp/fdo_e2e_test/mfg_config.yaml

# Onboarding Service
cd /var/bkgdata/go-fdo-onboarding-service
./fdo-onboarding-service -config /tmp/fdo_e2e_test/onboarding_config.yaml

# Device DI
cd /var/bkgdata/go-fdo-endpoint
rm -f /tmp/fdo_e2e_test/cred.bin
./fdo-client -config /tmp/fdo_e2e_test/device_config.cfg -di http://127.0.0.1:8081

# Device TO2 (direct)
cd /var/bkgdata/go-fdo-endpoint
./fdo-client -config /tmp/fdo_e2e_test/device_config.cfg -to2 http://127.0.0.1:8082
```

---

## Cleanup

The script traps `EXIT` and automatically stops both services plus cleans port usage. Manual cleanup, if necessary:

```bash
pkill -f "fdo-manufacturing-station.*8081" || true
pkill -f "fdo-onboarding-service.*8082" || true
rm -rf /tmp/fdo_e2e_test
```

---

## Troubleshooting

- **Ports busy** – `lsof -ti :8081 \| xargs kill -9` (repeat for port 8082).
- **Build failures** – ensure Go ≥1.21 and run `git submodule update --init --recursive` in all three repos.
- **DI fails** – inspect `manufacturing.log`, ensure the service reports "Listening" and is reachable via `curl http://127.0.0.1:8081`.
- **Voucher missing on onboarding** – confirm push token matches and look for "voucher transmission delivered" in `manufacturing.log`.
- **TO2 fails** – verify voucher exists under `/tmp/fdo_e2e_test/onboarding_vouchers`, inspect `onboarding.log` and `device_to2.log` for ownership/credential mismatches.
- **FSIM hostname missing** – ensure onboarding config retains the `fsim.sysconfig` entry and grep `hostname=E2Etest` inside the device log after rerunning TO2.

---

## Extending the Test

1. **Enable TO0/TO1** – configure rendezvous information properly in both configs and remove the direct `-to2` flag when invoking the client.
2. **Add more FSIM payloads** – populate `fsim.downloads`, `fsim.credentials`, or `payload_files` in the onboarding config to exercise richer service-info delivery.
3. **Multiple Devices** – clone `device_config.cfg`, adjust `blob_path` per device, and loop DI/TO2 runs to verify concurrent onboarding.
4. **Token Authentication Matrix** – replace the global token with DB-backed receiver tokens and update the manufacturing push settings accordingly.
5. **Credential Revocation** – extend the script to validate that revoked vouchers/credentials are rejected during TO2.

---

## Current Test Scope

- ✅ Device Initialization (DI)
- ✅ Voucher signover to onboarding owner key
- ✅ Voucher HTTP push with bearer token
- ✅ Transfer Ownership (TO2) with credential reuse
- ✅ FSIM sysconfig delivery (`hostname=E2Etest`)

Out of scope / TODO:

- ❌ TO0/TO1 rendezvous
- ❌ Full FSIM download/upload exercises
- ❌ Token rotation workflows
- ❌ Multi-device batch onboarding
- ❌ Credential revocation + audit trails

---

## Repository References

- Onboarding Service (this repo): `/var/bkgdata/go-fdo-onboarding-service`
- Manufacturing Station: `/home/windsurf/go-fdo-di`
- Device Client: `/var/bkgdata/go-fdo-endpoint`

Each contains its own README for deeper component-specific details.

---

## Support Checklist

1. Inspect `/tmp/fdo_e2e_test/*.log`
2. Confirm vouchers exist on both sides
3. Re-run build + `-init-only` phases if keys were modified
4. Consult the [FDO specification](https://fidoalliance.org/specs/fdo/) for protocol clarifications
