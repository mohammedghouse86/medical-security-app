# MedSecure — RBAC Map

Roles: **admin**, **doctor**, **patient**. Tenants are hospitals (`HOSP1001`, `HOSP1002`); a token carries `role` + `tenantId`.

> ⚠️ This app is a security-testing target. Several endpoints are **intentionally
> broken**. Below, **Intended** is what the role model *should* enforce and
> **Actual** is what the server currently allows. Rows where they differ are
> flagged **RBAC ISSUE** with an id that matches the code comments and
> `openapi.yaml` (`x-rbac-issue`).

Legend — access notation: `all` = every tenant, `tenant` = same tenant only,
`own` = only records belonging to the caller, `self` = caller's own account,
`—` = no access. "UI" = what the React app exposes; "API" = raw endpoint.

---

## 0. Cross-cutting: authentication

| Item | Intended | Actual | Status |
|------|----------|--------|--------|
| JWT signature | Verified (HS256) — tampering rejected | **Not verified**; payload trusted after expiry check only | 🔴 **RBAC ISSUE — VULN-AUTH**: forge/alter `role`/`tenantId` → full privilege escalation & cross-tenant access |

Because of VULN-AUTH, *every* "enforced" control below can also be bypassed by
forging a token. The per-endpoint rows describe behaviour assuming an
untampered token; VULN-AUTH is the master key that defeats all of them.

---

## 0b. Cross-cutting: mandatory API key

Every endpoint in the table below also requires an `X-API-Key` request header.
The key is simply the **base64 encoding of the username**, so it is constant per
user and carries no secret:

| User | Role | API key (`X-API-Key`) |
|------|------|----------------------|
| apollo.admin | admin | `YXBvbGxvLmFkbWlu` |
| sunrise.admin | admin | `c3VucmlzZS5hZG1pbg==` |
| apollo.doctor | doctor | `YXBvbGxvLmRvY3Rvcg==` |
| sunrise.doctor | doctor | `c3VucmlzZS5kb2N0b3I=` |
| apollo.patient | patient | `YXBvbGxvLnBhdGllbnQ=` |
| sunrise.patient | patient | `c3VucmlzZS5wYXRpZW50` |

The gate runs **before** `auth()`, so it applies to `/api/auth/login` and
`/api/health` as well. Only `/api/docs` and `/api/openapi.yaml` are exempt —
Swagger UI is a browser page that cannot set a header on its own load.

| Condition | Response |
|-----------|----------|
| No `X-API-Key` header (or blank) | `403 {"error":"API key is missing"}` |
| Header does not decode from base64, or decodes to an unknown username | `403 {"error":"API key is wrong"}` |
| Decodes to a username present in `data.json` | request proceeds to `auth()` |

> This is a **testing header, not a security control.** The key is a public,
> reversible encoding of a username, it is never checked against the bearer
> token, and any role's key opens any endpoint the token allows. It gates
> *presence of a known username*, nothing more.

---

## 1. Hospitals (basic)

| Method | Path | Intended | Actual | Status |
|--------|------|----------|--------|--------|
| GET | /api/hospitals | admin: all · others: own tenant | same | ✅ OK |
| GET | /api/hospitals/{id} | own tenant | **any tenant** | 🔴 RBAC-HOS (IDOR) |
| PUT | /api/hospitals/{id} | admin, own tenant | admin, **any tenant** | 🟠 RBAC-HOS-W |

## 2. Hospital Settings (owner, tax, finances, lawsuits)

| Method | Path | Intended | Actual | Status |
|--------|------|----------|--------|--------|
| GET | /api/hospital-settings | **admin only** | **any authenticated user** | 🔴 **VULN-HS** — UI shows 403 to doctor/patient, but the endpoint returns all tenants' financial/legal data |
| GET | /api/hospital-settings/{id} | **admin only** | **any authenticated user** | 🔴 VULN-HS |

> UI note: the Hospital Settings page is admin-only (doctor/patient see the 403
> screen). The **endpoint stays reachable** for them by design — this is the
> flagged issue, reproducible in the browser network tab.

## 3. Users

| Method | Path | Intended | Actual | Status |
|--------|------|----------|--------|--------|
| GET | /api/users | admin: tenant · others: self | same | ✅ OK |
| GET | /api/users/{id} | self / admin | **any user, incl. plaintext password** | 🔴 RBAC-USR (IDOR + credential exposure) |
| POST | /api/users | admin | admin (enforced) | ✅ OK |
| PUT | /api/users/{id} | admin, own tenant | admin, **any tenant** | 🟠 no tenant scoping |
| DELETE | /api/users/{id} | admin, own tenant | admin, **any tenant** | 🟠 no tenant scoping |

## 4. Patients

| Method | Path | Intended | Actual | Status |
|--------|------|----------|--------|--------|
| GET | /api/patients | admin: tenant · doctor: own · patient: self | same | ✅ OK |
| GET | /api/patients/{id} | tenant / assigned | **any patient** | 🔴 RBAC-01/09 (IDOR, PHI) |
| POST | /api/patients | admin | admin (enforced) | ✅ OK |
| PUT | /api/patients/{id} | admin / assigned doctor | **any authenticated user** | 🔴 RBAC-02 |
| DELETE | /api/patients/{id} | admin | admin, no tenant scope | 🟠 |
| **UI — Patients page** | — | **admin only** | admin only (nav + page); doctor/patient → 403 | ✅ (API still reachable — intended) |

## 5. Doctors

| Method | Path | Intended | Actual | Status |
|--------|------|----------|--------|--------|
| GET | /api/doctors | tenant | tenant | ✅ OK |
| GET | /api/doctors/{id} | tenant | **any doctor** | 🔴 RBAC-07 (IDOR) |
| POST | /api/doctors | admin | admin (enforced) | ✅ OK |
| PUT | /api/doctors/{id} | admin | **any authenticated user** | 🔴 RBAC-08 |
| DELETE | /api/doctors/{id} | admin | admin, no tenant scope | 🟠 |
| **UI — Doctors page** | — | **admin only** | admin only; doctor/patient → 403 | ✅ (API still reachable — intended) |

## 6. Appointments

| Method | Path | Intended | Actual | Status |
|--------|------|----------|--------|--------|
| GET | /api/appointments | admin: tenant · doctor: own · patient: own | same | ✅ OK |
| GET | /api/appointments/{id} | own / assigned | **any appointment** | 🔴 RBAC-10 (IDOR) |
| POST | /api/appointments | any auth (patient books own) | any auth | ✅ (UI auto-fills patientId for patients) |
| PUT | /api/appointments/{id} | admin / assigned / owner | **any authenticated user** | 🟠 RBAC-APT-W |
| DELETE | /api/appointments/{id} | admin / assigned / owner | **any authenticated user** | 🟠 RBAC-APT-D |

## 7. Reports

| Method | Path | Intended | Actual | Status |
|--------|------|----------|--------|--------|
| GET | /api/reports | patient: own · doctor: own · admin: tenant | **tenant for everyone** | 🔴 RBAC-RPT-L (patient sees all tenant reports) |
| GET | /api/reports/{id} | own / assigned | **any report** | 🔴 RBAC-03 (IDOR, PHI) |
| POST | /api/reports | admin / assigned doctor | any auth | 🟠 (UI restricts to admin + assigned doctor) |
| PUT | /api/reports/{id} | admin / assigned doctor | **any authenticated user** | 🔴 RBAC-RPT-W |
| DELETE | /api/reports/{id} | admin / assigned doctor | **any authenticated user** | 🔴 RBAC-RPT-D |
| **UI — edit/delete Report** | — | **admin + assigned doctor only** (patient read-only) | enforced in UI | ✅ (API still reachable — intended) |

## 8. Prescriptions

| Method | Path | Intended | Actual | Status |
|--------|------|----------|--------|--------|
| GET | /api/prescriptions | patient: own · admin: tenant | **tenant for everyone** | 🔴 RBAC-RX-L (leak to patient) |
| GET | /api/prescriptions/{id} | own / assigned | **any prescription** | 🔴 RBAC-RX-R (IDOR) |
| POST | /api/prescriptions | admin / doctor | **any auth, incl. patient** | 🔴 RBAC-04 |
| PUT | /api/prescriptions/{id} | admin / assigned doctor | **any authenticated user** | 🔴 RBAC-05 |
| DELETE | /api/prescriptions/{id} | admin / assigned doctor | **any authenticated user** | 🟠 RBAC-RX-D |

## 9. Medical Advice

| Method | Path | Intended | Actual | Status |
|--------|------|----------|--------|--------|
| GET | /api/advice | patient: own · doctor: own · admin: tenant | **tenant for everyone** | 🔴 RBAC-ADV-L (leak to patient) |
| POST | /api/advice | admin / assigned doctor | any auth | 🟠 (UI restricts to admin + assigned doctor) |
| PUT | /api/advice/{id} | admin / assigned doctor | **any authenticated user** | 🔴 RBAC-ADV-W |
| DELETE | /api/advice/{id} | admin / assigned doctor | **any authenticated user** | 🔴 RBAC-06 |
| **UI — edit/delete Advice** | — | **admin + assigned doctor only** (patient read-only) | enforced in UI | ✅ (API still reachable — intended) |

---

## Summary of intentional issues

| ID | Endpoint(s) | Class (OWASP API) |
|----|-------------|-------------------|
| VULN-AUTH | all (token) | API2 Broken Authentication |
| VULN-HS | GET /api/hospital-settings[/{id}] | API1 Broken Object Level / API5 Function Level |
| RBAC-01/09 | GET /api/patients/{id} | API1 BOLA |
| RBAC-02 | PUT /api/patients/{id} | API1 BOLA (write) |
| RBAC-03 | GET /api/reports/{id} | API1 BOLA |
| RBAC-04 | POST /api/prescriptions | API5 BFLA |
| RBAC-05 | PUT /api/prescriptions/{id} | API1 BOLA (write) |
| RBAC-06 | DELETE /api/advice/{id} | API1 BOLA (delete) |
| RBAC-07 | GET /api/doctors/{id} | API1 BOLA |
| RBAC-08 | PUT /api/doctors/{id} | API1 BOLA (write) |
| RBAC-10 | GET /api/appointments/{id} | API1 BOLA |
| RBAC-USR | GET /api/users/{id} | API1 BOLA + API3 Excessive Data (password) |
| RBAC-RPT-L / RX-L / ADV-L | list endpoints | API1 BOLA (patient over-read) |

**UI-only restrictions (intended “not accessible in UI, but API reachable”):**
Patients page, Doctors page, Hospital Settings page → admin-only in UI;
Report & Advice edit/delete → admin + assigned doctor only; patient record
lists (reports/appointments/advice/prescriptions) → scoped to self in UI.
In every one of these the underlying **endpoint remains reachable** — that gap
is the intended RBAC finding.
