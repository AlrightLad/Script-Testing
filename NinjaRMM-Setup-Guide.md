# NinjaRMM Setup Guide — Installer Patch Monitor

## 1. Create Device Custom Fields

In NinjaRMM: **Administration → Devices → Custom Fields → Add**

Create each field exactly as specified (field names are case-sensitive):

| Field Name | Field Type | Technician Permission | Automation Permission |
|---|---|---|---|
| installerFolderSizeGB | Decimal | Read Only | Read / Write |
| installerOrphanedSizeGB | Decimal | Read Only | Read / Write |
| installerOrphanedCount | Integer | Read Only | Read / Write |
| installerWinSxSSizeGB | Decimal | Read Only | Read / Write |
| installerStatus | Text | Read Only | Read / Write |
| installerLastScan | Text | Read Only | Read / Write |
| installerLastCleanup | Text | Read Only | Read / Write |
| installerCleanupRecoveredGB | Decimal | Read Only | Read / Write |

## 2. Upload Scripts to Script Library

Go to: **Administration → Library → Scripting**

### Monitor Script
- **Name:** DTC — Monitor Installer Patches
- **Language:** PowerShell
- **OS:** Windows
- **Architecture:** All
- **Run As:** System
- **Paste contents of** `Monitor-InstallerPatches.ps1`

### Cleanup Script
- **Name:** DTC — Cleanup Installer Patches
- **Language:** PowerShell
- **OS:** Windows
- **Architecture:** All
- **Run As:** System
- **Paste contents of** `Cleanup-InstallerPatches.ps1`
- **Script Parameters:** Add parameters for `WhatIf`, `SkipDISM`, `Force`, `QuarantineDays`

## 3. Create Scheduled Task for Monitor

Go to: **Administration → Policies → [Select target policy]**

Under **Scheduled Scripts:**
- **Script:** DTC — Monitor Installer Patches
- **Schedule:** Weekly, Sunday, 2:00 AM
- **Target:** All Windows devices (or specific device group)

## 4. Configure Condition-Based Alerts

Go to: **Administration → Policies → [Select target policy]**

Under **Conditions:**

### Warning Alert
- **Custom Field:** installerStatus
- **Condition:** Equals
- **Value:** Warning
- **Severity:** Warning
- **Notification:** Email DTC helpdesk
- **Ticket:** Create HALO ticket (if integrated)

### Critical Alert
- **Custom Field:** installerStatus
- **Condition:** Equals
- **Value:** Critical
- **Severity:** Critical
- **Notification:** Email DTC helpdesk + Slack channel
- **Ticket:** Create HALO ticket (if integrated)

### Error Alert
- **Custom Field:** installerStatus
- **Condition:** Equals
- **Value:** Error
- **Severity:** Critical
- **Notification:** Email DTC engineering
- **Ticket:** Create HALO ticket

## Event ID Reference

The monitor writes to the `Application` event log under source `DTC-InstallerMonitor`.
The cleanup script writes Event ID `1001` (Information) on completion.

| Event ID | Status | Entry Type | Description |
|----------|--------|------------|-------------|
| 1000 | Healthy | Information | Installer folder below warning threshold |
| 1001 | — | Information | Cleanup script completed successfully |
| 2000 | Warning | Warning | Installer folder >= warning threshold |
| 2500 | Critical | Error | Installer folder >= critical threshold |
| 3000 | Error | Error | Scan failure or critical error |

SIEM rules should target each Event ID independently — they are intentionally distinct
so filters can differentiate Warning from Critical severity.

## 5. AV Exclusion

Add to antivirus exclusion policy:
- **Path:** `C:\DTC\InstallerCleanup\` (quarantine folder — avoid AV scanning quarantined installer files)

## 6. Testing

1. Deploy monitor script to a test device manually
2. Verify custom fields populate in NinjaRMM device view
3. Run cleanup with `-WhatIf` first to verify detection accuracy
4. Review `-WhatIf` output — confirm flagged orphans are actually orphaned
5. Run cleanup without `-WhatIf` on test device
6. Verify quarantine folder created with orphaned files
7. Verify NinjaRMM custom fields updated post-cleanup
8. Enable scheduled task on broader device group
