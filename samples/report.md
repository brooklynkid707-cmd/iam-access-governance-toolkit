# Access Review Report

Snapshot date: **2026-10-15** | Source: `synthetic-directory-export`

## Inventory

| Users | Groups | Roles | Permissions | Privileged users |
|---:|---:|---:|---:|---:|
| 250 | 24 | 23 | 36 | 94 |

## Findings by severity

| Critical | High | Medium | Low | Info |
|---:|---:|---:|---:|---:|
| 26 | 47 | 59 | 4 | 0 |

## Findings by check

| Code | Count |
|---|---:|
| DORM-NO-LOGIN | 24 |
| LP-EXCESS | 19 |
| MFA-PRIV-MISSING | 18 |
| ORPHAN-MANAGER-GONE | 17 |
| LP-CREEP | 11 |
| MFA-MISSING | 10 |
| DORM-TERMINATED | 8 |
| ORPHAN-NO-MANAGER | 7 |
| SOD-005 | 7 |
| DORM-DISABLED-ACCESS | 4 |
| SOD-008 | 3 |
| SOD-001 | 2 |
| SOD-004 | 2 |
| SOD-002 | 2 |
| SOD-006 | 1 |
| SOD-003 | 1 |

## MFA compliance

- Human accounts enrolled: **195/223** (87.4%)
- Privileged accounts enrolled: **61/79** (77.2%)
- Service accounts (excluded from MFA requirement): 10
- Unenrolled by department: Engineering (9), Finance (6), HR (1), IT (5), Sales (3), Support (4)

## Separation-of-duties conflict matrix

| Rule | Users in conflict | Usernames |
|---|---:|---|
| SOD-001 | 2 | fcastellano2, efairweather |
| SOD-002 | 2 | fdelacroix, dcastellano2 |
| SOD-003 | 1 | mthornbury |
| SOD-004 | 2 | kyamada, mthornbury |
| SOD-005 | 7 | bvance, nlockwood, gellery2, myamada2, vsato, ajarvis2, svc-ci-deploy |
| SOD-006 | 1 | hgarnett |
| SOD-007 | 0 |  |
| SOD-008 | 3 | wfairweather, jvance, gbrennan2 |

## Top 15 riskiest identities

| # | User | Title | Dept | Score | Level | Why |
|---:|---|---|---|---:|---|---|
| 1 | hgarnett | IAM Administrator | IT | 84 | critical | +5 holds privileged access (inherent)<br>+19 5 permission(s) beyond title baseline<br>+40 MFA-PRIV-MISSING: Privileged user without MFA (3 high/critical permission(s))<br>+20 SoD conflict SOD-006: IAM administration + payment approval |
| 2 | fcastellano2 | Procurement Specialist | Finance | 82 | critical | +5 holds privileged access (inherent)<br>+17 4 permission(s) beyond title baseline<br>+40 MFA-PRIV-MISSING: Privileged user without MFA (3 high/critical permission(s))<br>+20 SoD conflict SOD-001: Vendor creation + payment approval |
| 3 | kyamada | Payroll Administrator | HR | 65 | high | +5 holds privileged access (inherent)<br>+5 privilege creep: 1 permission(s) from former title(s) HR Generalist<br>+40 MFA-PRIV-MISSING: Privileged user without MFA (2 high/critical permission(s))<br>+15 SoD conflict SOD-004: Employee record update + payroll run |
| 4 | bvance | Release Manager | Engineering | 60 | high | +5 holds privileged access (inherent)<br>+40 MFA-PRIV-MISSING: Privileged user without MFA (2 high/critical permission(s))<br>+15 SoD conflict SOD-005: Production deploy + deploy approval |
| 5 | mthornbury | Payroll Administrator | HR | 55 | high | +5 holds privileged access (inherent)<br>+15 3 permission(s) beyond title baseline<br>+20 SoD conflict SOD-003: Payroll run + payroll approval<br>+15 SoD conflict SOD-004: Employee record update + payroll run |
| 6 | kbarlow2 | Senior Software Engineer | Engineering | 53 | high | +5 holds privileged access (inherent)<br>+8 ORPHAN-MANAGER-GONE: Manager u0010 is terminated<br>+40 MFA-PRIV-MISSING: Privileged user without MFA (1 high/critical permission(s)) |
| 7 | bjarvis | Accounts Payable Manager | Finance | 45 | high | +5 holds privileged access (inherent)<br>+40 MFA-PRIV-MISSING: Privileged user without MFA (2 high/critical permission(s)) |
| 8 | fcastellano | Finance Director | Finance | 45 | high | +5 holds privileged access (inherent)<br>+40 MFA-PRIV-MISSING: Privileged user without MFA (2 high/critical permission(s)) |
| 9 | gholloway | Senior Software Engineer | Engineering | 45 | high | +5 holds privileged access (inherent)<br>+40 MFA-PRIV-MISSING: Privileged user without MFA (1 high/critical permission(s)) |
| 10 | isato2 | Senior Software Engineer | Engineering | 45 | high | +5 holds privileged access (inherent)<br>+40 MFA-PRIV-MISSING: Privileged user without MFA (1 high/critical permission(s)) |
| 11 | myamada | IAM Administrator | IT | 45 | high | +5 holds privileged access (inherent)<br>+40 MFA-PRIV-MISSING: Privileged user without MFA (1 high/critical permission(s)) |
| 12 | nabbott | Procurement Specialist | Finance | 45 | high | +5 holds privileged access (inherent)<br>+40 MFA-PRIV-MISSING: Privileged user without MFA (1 high/critical permission(s)) |
| 13 | pgarnett | Senior Software Engineer | Engineering | 45 | high | +5 holds privileged access (inherent)<br>+40 MFA-PRIV-MISSING: Privileged user without MFA (1 high/critical permission(s)) |
| 14 | qmarchetti | Accounts Payable Manager | Finance | 45 | high | +5 holds privileged access (inherent)<br>+40 MFA-PRIV-MISSING: Privileged user without MFA (2 high/critical permission(s)) |
| 15 | tellery | Senior Software Engineer | Engineering | 45 | high | +5 holds privileged access (inherent)<br>+40 MFA-PRIV-MISSING: Privileged user without MFA (1 high/critical permission(s)) |

## Critical and high findings

- **[CRITICAL] MFA-PRIV-MISSING** `bjarvis` (Accounts Payable Manager): Privileged user without MFA (2 high/critical permission(s))
- **[CRITICAL] MFA-PRIV-MISSING** `bvance` (Release Manager): Privileged user without MFA (2 high/critical permission(s))
- **[CRITICAL] SOD-002** `dcastellano2` (Accounts Payable Clerk): SoD conflict 'Payment creation + payment approval': holds finance.payments:create + finance.payments:approve
- **[CRITICAL] DORM-TERMINATED** `dunderhill2` (Senior Software Engineer): Account is still enabled although HR status is terminated (43 days ago) and the account holds privileged access
- **[CRITICAL] SOD-001** `efairweather` (Procurement Specialist): SoD conflict 'Vendor creation + payment approval': holds finance.vendors:create + finance.payments:approve
- **[CRITICAL] DORM-TERMINATED** `eunderhill` (Senior Software Engineer): Account is still enabled although HR status is terminated (75 days ago) and the account holds privileged access
- **[CRITICAL] MFA-PRIV-MISSING** `fcastellano` (Finance Director): Privileged user without MFA (2 high/critical permission(s))
- **[CRITICAL] MFA-PRIV-MISSING** `fcastellano2` (Procurement Specialist): Privileged user without MFA (3 high/critical permission(s))
- **[CRITICAL] SOD-001** `fcastellano2` (Procurement Specialist): SoD conflict 'Vendor creation + payment approval': holds finance.vendors:create + finance.payments:approve
- **[CRITICAL] SOD-002** `fdelacroix` (Accounts Payable Clerk): SoD conflict 'Payment creation + payment approval': holds finance.payments:create + finance.payments:approve
- **[CRITICAL] MFA-PRIV-MISSING** `gholloway` (Senior Software Engineer): Privileged user without MFA (1 high/critical permission(s))
- **[CRITICAL] MFA-PRIV-MISSING** `hgarnett` (IAM Administrator): Privileged user without MFA (3 high/critical permission(s))
- **[CRITICAL] SOD-006** `hgarnett` (IAM Administrator): SoD conflict 'IAM administration + payment approval': holds it.iam:admin + finance.payments:approve
- **[CRITICAL] MFA-PRIV-MISSING** `isato2` (Senior Software Engineer): Privileged user without MFA (1 high/critical permission(s))
- **[CRITICAL] MFA-PRIV-MISSING** `kbarlow2` (Senior Software Engineer): Privileged user without MFA (1 high/critical permission(s))
- **[CRITICAL] MFA-PRIV-MISSING** `kyamada` (Payroll Administrator): Privileged user without MFA (2 high/critical permission(s))
- **[CRITICAL] SOD-003** `mthornbury` (Payroll Administrator): SoD conflict 'Payroll run + payroll approval': holds hr.payroll:run + hr.payroll:approve
- **[CRITICAL] MFA-PRIV-MISSING** `myamada` (IAM Administrator): Privileged user without MFA (1 high/critical permission(s))
- **[CRITICAL] MFA-PRIV-MISSING** `nabbott` (Procurement Specialist): Privileged user without MFA (1 high/critical permission(s))
- **[CRITICAL] MFA-PRIV-MISSING** `pgarnett` (Senior Software Engineer): Privileged user without MFA (1 high/critical permission(s))
- **[CRITICAL] MFA-PRIV-MISSING** `qmarchetti` (Accounts Payable Manager): Privileged user without MFA (2 high/critical permission(s))
- **[CRITICAL] MFA-PRIV-MISSING** `tellery` (Senior Software Engineer): Privileged user without MFA (1 high/critical permission(s))
- **[CRITICAL] MFA-PRIV-MISSING** `usato` (Senior Software Engineer): Privileged user without MFA (1 high/critical permission(s))
- **[CRITICAL] MFA-PRIV-MISSING** `vquigley` (Backup Operator): Privileged user without MFA (1 high/critical permission(s))
- **[CRITICAL] MFA-PRIV-MISSING** `xlockwood` (Accounts Payable Manager): Privileged user without MFA (2 high/critical permission(s))
- **[CRITICAL] MFA-PRIV-MISSING** `ypemberton2` (IAM Administrator): Privileged user without MFA (1 high/critical permission(s))
- **[HIGH] LP-CREEP** `agarnett` (Help Desk Technician): Privilege creep: 1 permission(s) retained from former title(s) IAM Administrator
- **[HIGH] SOD-005** `ajarvis2` (Release Manager): SoD conflict 'Production deploy + deploy approval': holds eng.prod:deploy + eng.prod:approve_deploy (all via the same assignment - fix the role, not the user)
- **[HIGH] LP-EXCESS** `ajarvis3` (Help Desk Technician): 1 permission(s) exceed the 'Help Desk Technician' baseline (highest sensitivity: critical)
- **[HIGH] LP-EXCESS** `avance` (Software Engineer): 1 permission(s) exceed the 'Software Engineer' baseline (highest sensitivity: critical)
- **[HIGH] DORM-NO-LOGIN** `bquigley` (HR Generalist): No login for 323 days (threshold 90)
- **[HIGH] SOD-005** `bvance` (Release Manager): SoD conflict 'Production deploy + deploy approval': holds eng.prod:deploy + eng.prod:approve_deploy (all via the same assignment - fix the role, not the user)
- **[HIGH] LP-EXCESS** `dcastellano2` (Accounts Payable Clerk): 1 permission(s) exceed the 'Accounts Payable Clerk' baseline (highest sensitivity: critical)
- **[HIGH] LP-EXCESS** `efairweather` (Procurement Specialist): 4 permission(s) exceed the 'Procurement Specialist' baseline (highest sensitivity: critical)
- **[HIGH] DORM-NO-LOGIN** `erasmussen` (Procurement Specialist): No login for 150 days (threshold 90)
- **[HIGH] LP-CREEP** `fabbott` (Accounts Payable Clerk): Privilege creep: 2 permission(s) retained from former title(s) Procurement Specialist
- **[HIGH] LP-EXCESS** `fcastellano2` (Procurement Specialist): 4 permission(s) exceed the 'Procurement Specialist' baseline (highest sensitivity: critical)
- **[HIGH] LP-EXCESS** `fdelacroix` (Accounts Payable Clerk): 1 permission(s) exceed the 'Accounts Payable Clerk' baseline (highest sensitivity: critical)
- **[HIGH] DORM-TERMINATED** `fnavarro` (Help Desk Technician): Account is still enabled although HR status is terminated (66 days ago)
- **[HIGH] LP-EXCESS** `gbrennan2` (Systems Administrator): 1 permission(s) exceed the 'Systems Administrator' baseline (highest sensitivity: critical)
- **[HIGH] SOD-008** `gbrennan2` (Systems Administrator): SoD conflict 'Backup deletion + server administration': holds it.backups:delete + it.servers:admin
- **[HIGH] LP-EXCESS** `gellery2` (Senior Software Engineer): 1 permission(s) exceed the 'Senior Software Engineer' baseline (highest sensitivity: high)
- **[HIGH] SOD-005** `gellery2` (Senior Software Engineer): SoD conflict 'Production deploy + deploy approval': holds eng.prod:deploy + eng.prod:approve_deploy
- **[HIGH] DORM-TERMINATED** `gpemberton` (Support Agent): Account is still enabled although HR status is terminated (8 days ago)
- **[HIGH] LP-EXCESS** `hgarnett` (IAM Administrator): 5 permission(s) exceed the 'IAM Administrator' baseline (highest sensitivity: critical)
- **[HIGH] LP-EXCESS** `iashdown` (Software Engineer): 1 permission(s) exceed the 'Software Engineer' baseline (highest sensitivity: high)
- **[HIGH] DORM-TERMINATED** `iokafor` (Software Engineer): Account is still enabled although HR status is terminated (106 days ago)
- **[HIGH] LP-EXCESS** `jnavarro` (Sales Representative): 1 permission(s) exceed the 'Sales Representative' baseline (highest sensitivity: high)
- **[HIGH] LP-EXCESS** `jvance` (Systems Administrator): 1 permission(s) exceed the 'Systems Administrator' baseline (highest sensitivity: critical)
- **[HIGH] SOD-008** `jvance` (Systems Administrator): SoD conflict 'Backup deletion + server administration': holds it.backups:delete + it.servers:admin
- **[HIGH] LP-CREEP** `kellery2` (Help Desk Technician): Privilege creep: 2 permission(s) retained from former title(s) Backup Operator
- **[HIGH] LP-CREEP** `kyamada` (Payroll Administrator): Privilege creep: 1 permission(s) retained from former title(s) HR Generalist
- **[HIGH] SOD-004** `kyamada` (Payroll Administrator): SoD conflict 'Employee record update + payroll run': holds hr.employees:update + hr.payroll:run
- **[HIGH] DORM-TERMINATED** `lunderhill` (Accounts Payable Clerk): Account is still enabled although HR status is terminated (57 days ago)
- **[HIGH] LP-EXCESS** `mthornbury` (Payroll Administrator): 3 permission(s) exceed the 'Payroll Administrator' baseline (highest sensitivity: high)
- **[HIGH] SOD-004** `mthornbury` (Payroll Administrator): SoD conflict 'Employee record update + payroll run': holds hr.employees:update + hr.payroll:run
- **[HIGH] LP-EXCESS** `myamada2` (Senior Software Engineer): 1 permission(s) exceed the 'Senior Software Engineer' baseline (highest sensitivity: high)
- **[HIGH] SOD-005** `myamada2` (Senior Software Engineer): SoD conflict 'Production deploy + deploy approval': holds eng.prod:deploy + eng.prod:approve_deploy
- **[HIGH] DORM-TERMINATED** `nbrennan` (Sales Representative): Account is still enabled although HR status is terminated (56 days ago)
- **[HIGH] DORM-NO-LOGIN** `ngarnett` (Staff Accountant): Enabled account has never logged in (created 195 days ago)
- **[HIGH] SOD-005** `nlockwood` (Release Manager): SoD conflict 'Production deploy + deploy approval': holds eng.prod:deploy + eng.prod:approve_deploy
- **[HIGH] LP-EXCESS** `nthornbury` (Sales Representative): 1 permission(s) exceed the 'Sales Representative' baseline (highest sensitivity: high)
- **[HIGH] LP-CREEP** `pvance2` (Software Engineer): Privilege creep: 5 permission(s) retained from former title(s) Systems Administrator
- **[HIGH] DORM-TERMINATED** `pvance3` (Support Agent): Account is still enabled although HR status is terminated (66 days ago)
- **[HIGH] DORM-NO-LOGIN** `qabbott2` (Systems Administrator): No login for 275 days (threshold 90)
- **[HIGH] SOD-005** `svc-ci-deploy` (Service Account): SoD conflict 'Production deploy + deploy approval': holds eng.prod:deploy + eng.prod:approve_deploy (all via the same assignment - fix the role, not the user)
- **[HIGH] DORM-NO-LOGIN** `svc-crm-etl` (Service Account): No login for 400 days (threshold 90)
- **[HIGH] DORM-NO-LOGIN** `svc-legacy-erp` (Service Account): No login for 300 days (threshold 90)
- **[HIGH] DORM-NO-LOGIN** `uabbott` (Senior Software Engineer): No login for 165 days (threshold 90)
- **[HIGH] SOD-005** `vsato` (Release Manager): SoD conflict 'Production deploy + deploy approval': holds eng.prod:deploy + eng.prod:approve_deploy (all via the same assignment - fix the role, not the user)
- **[HIGH] LP-EXCESS** `wfairweather` (Systems Administrator): 1 permission(s) exceed the 'Systems Administrator' baseline (highest sensitivity: critical)
- **[HIGH] SOD-008** `wfairweather` (Systems Administrator): SoD conflict 'Backup deletion + server administration': holds it.backups:delete + it.servers:admin
- **[HIGH] DORM-NO-LOGIN** `xrasmussen` (Senior Software Engineer): No login for 111 days (threshold 90)

## Role mining suggestions

| Cluster | Suggested role | Members | Core perms | Optional perms | Closest existing role | Cohesion |
|---:|---|---:|---:|---:|---|---:|
| 1 | mined_software_engineer | 65 | 6 | 3 | title:Software Engineer (1.00) | 0.93 |
| 2 | mined_support_agent | 49 | 6 | 3 | title:Support Agent (1.00) | 0.98 |
| 3 | mined_sales_representative | 43 | 5 | 1 | title:Sales Representative (1.00) | 0.98 |
| 4 | mined_finance_common | 11 | 7 | 6 | title:Accounts Payable Manager (0.88) | 0.83 |
| 8 | mined_help_desk_technician | 10 | 6 | 4 | title:Help Desk Technician (0.86) | 0.82 |
| 5 | mined_hr_generalist | 7 | 5 | 2 | title:HR Generalist (1.00) | 0.96 |
| 6 | mined_staff_accountant | 7 | 6 | 3 | title:Staff Accountant (1.00) | 0.94 |
| 9 | mined_engineering_common | 6 | 7 | 2 | title:Engineering Manager (1.00) | 0.89 |
| 7 | mined_procurement_specialist | 5 | 6 | 0 | title:Procurement Specialist (1.00) | 1.00 |
| 11 | mined_systems_administrator | 4 | 8 | 1 | title:Systems Administrator (1.00) | 0.92 |
| 10 | mined_release_manager | 3 | 6 | 0 | title:Release Manager (1.00) | 1.00 |
| 12 | mined_iam_administrator | 3 | 5 | 0 | title:IAM Administrator (1.00) | 1.00 |

## Access-review campaign packets

| Reviewer | File | Users | Entitlement rows | Flagged rows |
|---|---|---:|---:|---:|
| _unassigned | _unassigned.csv | 25 | 156 | 156 |
| ajarvis | ajarvis.csv | 23 | 136 | 31 |
| arasmussen | arasmussen.csv | 22 | 139 | 22 |
| byamada | byamada.csv | 16 | 83 | 23 |
| cjarvis | cjarvis.csv | 16 | 85 | 10 |
| fcastellano | fcastellano.csv | 9 | 63 | 18 |
| gmarchetti | gmarchetti.csv | 9 | 46 | 11 |
| icalder | icalder.csv | 26 | 158 | 38 |
| jrasmussen | jrasmussen.csv | 16 | 113 | 34 |
| kellery | kellery.csv | 9 | 63 | 12 |
| kfairweather | kfairweather.csv | 11 | 55 | 15 |
| kholloway | kholloway.csv | 24 | 171 | 68 |
| lfairweather | lfairweather.csv | 16 | 109 | 44 |
| rabbott | rabbott.csv | 14 | 98 | 9 |
| yquigley | yquigley.csv | 14 | 90 | 12 |

## Data integrity issues

- user crasmussen references unknown group g-legacy-fileshare
