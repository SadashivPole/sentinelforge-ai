# Security Policy

**Project:** SentinelForge AI  
**Version:** 0.1.0 (prototype)

---

## 1. Supported Versions

| Version | Supported |
|---|---|
| 0.1.0 (current prototype) | ✅ Yes |

---

## 2. Reporting a Vulnerability

**Do not open public issues for security vulnerabilities.** Security issues should be reported privately to the project maintainer.

To report a vulnerability:

1. Create a private draft issue or contact the repository owner through GitHub's private vulnerability reporting feature.
2. Include the details listed below.
3. Do not disclose the vulnerability publicly until it has been addressed or the disclosure timeline has elapsed.

Include:
- Description of the vulnerability
- Steps to reproduce
- Affected components and versions
- Potential impact
- Suggested remediation (if any)

We will acknowledge receipt within 5 business days and provide a remediation timeline within 10 business days.

---

## 3. Security Properties of This Prototype

SentinelForge AI is designed with the following security properties:

| Property | Implementation |
|---|---|
| No automatic remediation | Detection rules produce alerts only; no blocking, isolation, or remediation |
| Log content never executed | Command strings in logs are inspected as text only |
| Parameterized SQL | All database queries use `?` placeholders; no string interpolation of user data |
| Raw evidence immutable | Original log payloads preserved verbatim; never modified during analysis |
| No credentials in source | All configuration from `SENTINELFORGE_*` environment variables |
| Mock AI provider | Default AI provider is mock; no network calls by default |
| SQL injection safe | Values stored literally via parameterized queries |
| Foreign key enforcement | SQLite `PRAGMA foreign_keys = ON` on all connections |

---

## 4. What Is NOT Covered

This is a **prototype**, not a production system. The following are NOT implemented:

- Authentication / authorization / RBAC
- Encryption at rest for SQLite database
- Network encryption / TLS
- Audit logging for administrative actions
- Real-time threat intelligence
- Production deployment hardening

Do not deploy this prototype to production environments or use it with real customer data without first addressing these gaps.

---

## 5. Disclosure Timeline

| Milestone | Target |
|---|---|
| Initial acknowledgment | 5 business days |
| Remediation timeline | 10 business days |
| Status updates | Every 10 business days |
| Public disclosure | After fix is available or 90 days, whichever comes first |

---

## 6. Acknowledgements

We thank security researchers who responsibly disclose vulnerabilities. Contributors are acknowledged in release notes.