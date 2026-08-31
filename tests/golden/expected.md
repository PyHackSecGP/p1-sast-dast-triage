# SAST+DAST Triage Report

## Summary

| Metric | Value |
|---|---|
| Total findings | 12 |
| Active (needs review) | 12 |
| False positives filtered | 0 |
| Suppressed | 0 |

### By Severity (true positives)

| Severity | | Count |
|---|---|---|
| Critical | 🔴 | 1 |
| High | 🟠 | 6 |
| Medium | 🟡 | 2 |
| Low | 🔵 | 2 |
| Info | ⚪ | 1 |

## Findings

| Severity | Rule | Scanners | Title | Location | Risk Score | Confidence | Notes |
|---|---|---|---|---|---|---|---|
| 🔴 CRITICAL | `CVE-2022-1000` | trivy  | CVE-2022-1000: openssl 3.0.0 | `example.local/app:1.0 (alpine 3.18.0)` | 9.5 | — | ⚠ unreviewed |
| 🟠 HIGH | `python.lang.security.audit.sqli.raw-query-format-string` | semgrep x2 | raw-query-format-string | `app/db.py:42` | 9.0 | — | ⚠ unreviewed |
| 🟠 HIGH | `40012` | zap  | Cross Site Scripting (Reflected) | `http://localhost:5000/search?q=test` | 8.0 | — | ⚠ unreviewed |
| 🟠 HIGH | `CVE-2023-52425` | trivy  | CVE-2023-52425: libexpat 2.5.0-r0 | `example.local/app:1.0 (alpine 3.18.0)` | 7.5 | — | ⚠ unreviewed |
| 🟠 HIGH | `DS002` | trivy  | Image user should not be 'root' | `app/Dockerfile:12` | 7.5 | — | ⚠ unreviewed |
| 🟠 HIGH | `aws-access-key-id` | trivy  | AWS Access Key ID | `app/config/settings.py:4` | 8.5 | — | ⚠ unreviewed |
| 🟠 HIGH | `CVE-2022-0778` | nuclei  | OpenSSL 3.0.0-3.0.2 - Denial of Service | `http://example.local/` | 7.5 | — | ⚠ unreviewed |
| 🟡 MEDIUM | `python.flask.security.audit.hardcoded-secret` | semgrep  | hardcoded-secret | `config.py:8` | 6.5 | — | ⚠ unreviewed |
| 🟡 MEDIUM | `git-config` | nuclei  | .git/config Exposure | `http://example.local/.git/config` | 5.5 | — | ⚠ unreviewed |
| 🔵 LOW | `B105` | bandit  | hardcoded_password_string | `auth/login.py:15` | 2.5 | — | ⚠ unreviewed |
| 🔵 LOW | `10021` | zap  | X-Content-Type-Options Header Missing | `http://localhost:5000/` | 2.5 | — | ⚠ unreviewed |
| ⚪ INFO | `wordpress-detect` | nuclei  | WordPress Detection | `http://example.local/wp-login.php` | 0.0 | — | ⚠ unreviewed |

---

### 🔴 CVE-2022-1000: openssl 3.0.0
**Scanner:** trivy | **Rule:** `CVE-2022-1000` | **Severity:** CRITICAL | **Risk Score:** 9.5
**Location:** `example.local/app:1.0 (alpine 3.18.0)`

Hypothetical critical OpenSSL issue for fixture data. Fixed in: 3.0.7.

**CWE:** CWE-125

### 🟠 raw-query-format-string
**Scanner:** semgrep | **Rule:** `python.lang.security.audit.sqli.raw-query-format-string` | **Severity:** HIGH | **Risk Score:** 9.0
**Location:** `app/db.py:42`
**Reported by:** `semgrep:python.lang.security.audit.sqli.raw-query-format-string`, `bandit:B608`

Detected SQL statement formatted with a Python string. This is vulnerable to SQL injection. Use parameterized queries instead.

**CWE:** CWE-89

```
cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
```

### 🟠 Cross Site Scripting (Reflected)
**Scanner:** zap | **Rule:** `40012` | **Severity:** HIGH | **Risk Score:** 8.0
**Location:** `http://localhost:5000/search?q=test`

Cross-site Scripting (XSS) is an attack where malicious scripts are injected into otherwise benign and trusted web sites. Phase: Architecture and Design — Use a vetted library or framework that does not allow this weakness to occur or provides constructs that make this weakness easier to avoid.

**CWE:** CWE-79

```
GET http://localhost:5000/search?q=test
Evidence: <script>alert(1)</script>
```

### 🟠 CVE-2023-52425: libexpat 2.5.0-r0
**Scanner:** trivy | **Rule:** `CVE-2023-52425` | **Severity:** HIGH | **Risk Score:** 7.5
**Location:** `example.local/app:1.0 (alpine 3.18.0)`

Expat before 2.6.0 allows a denial of service via oversized XML input. Fixed in: 2.5.0-r1.

**CWE:** CWE-611

### 🟠 Image user should not be 'root'
**Scanner:** trivy | **Rule:** `DS002` | **Severity:** HIGH | **Risk Score:** 7.5
**Location:** `app/Dockerfile:12`

Running containers with 'root' user could lead to a container escape situation.

**CWE:** CWE-250

### 🟠 AWS Access Key ID
**Scanner:** trivy | **Rule:** `aws-access-key-id` | **Severity:** HIGH | **Risk Score:** 8.5
**Location:** `app/config/settings.py:4`

AKIAIOSFODNN7EXAMPLE

**CWE:** CWE-798

### 🟠 OpenSSL 3.0.0-3.0.2 - Denial of Service
**Scanner:** nuclei | **Rule:** `CVE-2022-0778` | **Severity:** HIGH | **Risk Score:** 7.5
**Location:** `http://example.local/`

tls-version

**CWE:** CWE-835

### 🟡 hardcoded-secret
**Scanner:** semgrep | **Rule:** `python.flask.security.audit.hardcoded-secret` | **Severity:** MEDIUM | **Risk Score:** 6.5
**Location:** `config.py:8`

Hardcoded secret key detected. Move this to an environment variable.

**CWE:** CWE-798

```
SECRET_KEY = 'super-secret-hardcoded-key-123'
```

### 🟡 .git/config Exposure
**Scanner:** nuclei | **Rule:** `git-config` | **Severity:** MEDIUM | **Risk Score:** 5.5
**Location:** `http://example.local/.git/config`

A .git/config file was discovered on the server.

**CWE:** CWE-538

### 🔵 hardcoded_password_string
**Scanner:** bandit | **Rule:** `B105` | **Severity:** LOW | **Risk Score:** 2.5
**Location:** `auth/login.py:15`

Possible hardcoded password: 'admin123'.

**CWE:** CWE-259

```
DEFAULT_PASSWORD = 'admin123'
```

### 🔵 X-Content-Type-Options Header Missing
**Scanner:** zap | **Rule:** `10021` | **Severity:** LOW | **Risk Score:** 2.5
**Location:** `http://localhost:5000/`

The Anti-MIME-Sniffing header X-Content-Type-Options was not set to nosniff.

**CWE:** CWE-693

### ⚪ WordPress Detection
**Scanner:** nuclei | **Rule:** `wordpress-detect` | **Severity:** INFO | **Risk Score:** 0.0
**Location:** `http://example.local/wp-login.php`

WordPress version detected.