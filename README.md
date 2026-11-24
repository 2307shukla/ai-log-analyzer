# AI Log Analyzer

An AI-assisted security log analyzer built with **Spring Boot 3** and **Spring AI**, running on **Google Gemini's free tier**.

Upload a log in any of ten formats (web, SSH, Linux syslog, JSON lines, Spring Boot, Windows Security events, AWS CloudTrail, UFW/iptables, Docker/Kubernetes, or anything else). The format is detected automatically, and you can override it. The app detects attack patterns deterministically, scores the risk, maps each finding to **MITRE ATT&CK**, draws a request timeline, then has an LLM write a readable incident report. Reports can be downloaded as Markdown or JSON, and you can **chat with the log**: ask questions like "Which IP should I block?" and get answers grounded only in what the log shows.

**Live demo:** https://ai-log-analyzer-5l3n.onrender.com

---

## Why two stages

Most "AI log analyzer" projects paste raw logs into a model and hope. That is expensive, slow, and hallucinates attacks that never happened.

This project splits the work:

| Stage | What runs | Cost |
|---|---|---|
| **1. Detection** | Plain Java. Counts, ratios, pattern matching over parsed events | Free, instant, reproducible |
| **2. Explanation** | LLM receives *only the computed summary* | One small API call |

The model reasons over verified numbers, never raw text. A 50 MB log is reduced to a few hundred bytes of JSON before any API call, so it works comfortably inside a free tier.

---

## Detection rules

Implemented locally in [`FindingDetector`](src/main/java/com/abhijeet/loganalyzer/service/FindingDetector.java) (web and authentication) and [`PlatformRules`](src/main/java/com/abhijeet/loganalyzer/service/PlatformRules.java) (Windows, Linux, cloud, firewall, application, containers). Every finding carries a severity, a MITRE ATT&CK technique from the static table in [`MitreMapping`](src/main/java/com/abhijeet/loganalyzer/service/MitreMapping.java) where one applies, a count, up to five pieces of evidence, and a recommendation.

| Rule | Severity | MITRE ATT&CK | Fires when |
|---|---|---|---|
| `COMPROMISED_LOGIN` | CRITICAL | T1078 | An address logs in successfully after 3+ failures (SSH, Windows 4624, AWS console) |
| `BRUTE_FORCE` | MEDIUM–CRITICAL | T1110 | 3+ failed logins from one address (HIGH at 10, CRITICAL at 50) |
| `PASSWORD_SPRAYING` | HIGH | T1110.003 | One address tries 5+ account names |
| `WEB_LOGIN_BRUTE_FORCE` | HIGH | T1110.001 | 10+ login POSTs from one address (`/login`, `wp-login.php`, `xmlrpc.php`, …) |
| `SSH_ROOT_LOGIN` | MEDIUM / HIGH | T1078.003 | SSH logins attempted as root (HIGH if 10+ or one succeeded) |
| `SQL_INJECTION` / `PATH_TRAVERSAL` | HIGH | T1190 | Attack syntax in the URL, URL-decoded first |
| `XSS` | MEDIUM | T1190 | Script or event-handler payloads in the URL |
| `SENSITIVE_PATH_PROBING` / `FORCED_BROWSING` | MEDIUM / HIGH | T1595.003 | `.env`, `.git`, admin panels; 10+ distinct 404s from one address |
| `SCANNER_USER_AGENT` | MEDIUM | T1595.002 | sqlmap, nikto, nmap, zgrab, … |
| `SERVER_ERRORS` | MEDIUM / HIGH | | 3+ responses with a 5xx status |
| `REQUEST_BURST` | MEDIUM / HIGH | T1498 | Busiest minute 5x the median and 20+ requests |
| `TRAFFIC_CONCENTRATION` | LOW | | One address makes a third of all web requests |
| `SUDO_SU_USAGE` | LOW / MEDIUM | T1548.003 | sudo commands and su sessions (MEDIUM when a shell or account/sudoers change is involved) |
| `SUDO_SU_FAILURES` | MEDIUM | T1548.003 | 3+ failed sudo or su attempts |
| `ACCOUNT_CREATED` | MEDIUM | T1136.001 | Windows 4720 or Linux `useradd` |
| `PRIVILEGED_GROUP_CHANGE` | HIGH | T1098 | Windows 4728/4732/4756 or Linux add to sudo/wheel/adm/docker |
| `PRIVILEGE_USE` | LOW | T1078.002 | Windows 4672/4673/4674 |
| `ACCOUNT_LOCKOUT` | MEDIUM | T1110 | Windows 4740 |
| `AUDIT_LOG_CLEARED` | CRITICAL | T1070.001 | Windows 1102 |
| `CONSOLE_LOGIN_WITHOUT_MFA` | HIGH | T1078.004 | AWS console sign-in with MFAUsed = No |
| `ROOT_ACCOUNT_USAGE` | HIGH / CRITICAL | T1078.004 | Any AWS root activity (CRITICAL for a console sign-in) |
| `IAM_CHANGES` | MEDIUM / HIGH | T1098 | IAM create/attach/put/delete calls (HIGH when they grant access) |
| `DELETED_RESOURCES` | MEDIUM / HIGH | T1485 | Successful Delete*/Terminate* calls (HIGH for buckets, databases, snapshots, instances, keys) |
| `CLOUD_LOGGING_DISABLED` | CRITICAL | T1562.008 | StopLogging, DeleteTrail, DeleteDetector, DeleteFlowLogs |
| `PORT_SCAN` | HIGH | T1046 | One source hits 10+ destination ports |
| `FIREWALL_BLOCKS` | LOW / MEDIUM | | 20+ blocked connections |
| `APP_EXCEPTIONS` | MEDIUM / HIGH | | 3+ Java exceptions, grouped by class with root causes |
| `ERROR_BURST` | MEDIUM / HIGH | | 10+ ERROR lines in one minute and 3x the usual error minute |
| `CRASH_LOOP` | HIGH / CRITICAL | | CrashLoopBackOff / back-off restarting |
| `OOM_KILL` | HIGH | | OOMKilled or kernel out-of-memory kills |
| `PROBE_FAILURES` / `IMAGE_PULL_ERRORS` | MEDIUM | | Failing liveness/readiness probes; ErrImagePull |

**Risk score.** Each finding adds its severity weight (CRITICAL 40, HIGH 25, MEDIUM 12, LOW 4), capped at 100. The overall level is the higher of the score band (70+ CRITICAL, 40+ HIGH, 15+ MEDIUM, otherwise LOW) and the most serious single finding, so one critical issue is never hidden behind a low total. A log with no findings is `CLEAN`.

Everything that came from the log is untrusted text. Evidence is clipped, stripped of control characters, and escaped wherever it is rendered (dashboard and Markdown export).

---

## Analysis features

### Charts
Requests and errors over time, drawn with [Chart.js](https://www.chartjs.org) (MIT), served from `/vendor/chart.umd.min.js` with no CDN. Errors are split into 4xx, 5xx, failed logins and application/system errors. Buckets are automatic, per minute or per hour (`GET /api/logs/timeline?bucket=`). A bucket counts as a **spike** when it is at least 3x the usual bucket and at least 10 events (5 for errors); spikes are drawn in red.

### Suspicious IPs and GeoIP
Every source address is scored 0–100 from what it did (breaking in after failures, failed logins, injection requests, scanners, probes, port scans, firewall blocks, cloud logging or IAM changes) and the top 10 are shown with the reasons. Severity bands match the overall risk: 70+ critical, 40+ high, 15+ medium.

Locations come from the free, offline **[DB-IP City Lite](https://db-ip.com/db/download/ip-to-city-lite)** database (CC BY 4.0, no account or key), read with MaxMind's open-source reader. The Docker build downloads it; the file is memory-mapped, so it does not use Java heap. Private, loopback and documentation addresses are never looked up, host names are never resolved, and no lookup leaves the server. **If the file is missing, GeoIP is skipped** and everything else works. Build with `--build-arg GEOIP_EDITION=country` for a smaller image (countries only) or `none` to leave it out.

### Alert rules
Rules live in [`alert-rules.yml`](src/main/resources/alert-rules.yml) (20 bundled rules). Point `ALERT_RULES_FILE` at your own YAML or JSON file to replace them; invalid rules are skipped and listed at `GET /api/alerts/rules`.

```yaml
rules:
  - id: brute-force-burst
    name: More than 5 failed logins from one IP in 1 minute
    metric: failed_logins     # 17 event metrics, plus risk_score and finding
    groupBy: ip               # ip, user or global
    threshold: 5              # fires when the count is greater (operator: gte for >=)
    windowMinutes: 1          # sliding window; 0 = whole log
    severity: high            # low, medium, high, critical
```

Triggered alerts appear at the top of the dashboard, in the summary JSON and in the exports.

### Reports and exports
All exports are built from the deterministic findings, so they never call the model. If the AI incident report has already been written for the loaded log, it is included.

| Format | Contents |
|---|---|
| **PDF** (`format=pdf`) | Risk score, detected format, triggered alerts, every finding with MITRE technique, evidence and fix, top offenders with location, request and error charts (vector bars), status codes, and the AI incident report. Built with [Apache PDFBox](https://pdfbox.apache.org) (Apache-2.0). |
| **CSV** (`format=csv`) | One row per finding: severity, rule, title, MITRE, count, description, evidence, recommendation. Cells that a spreadsheet would run as formulas are neutralised. |
| **JSON** (`format=json`) | The full summary (findings, alerts, offenders, timeline) plus the AI report when present. |
| **Markdown** (`format=md`) | A readable report for tickets and wikis. |

### Chat with the log
Ask questions in plain language ("Which IP should I block?", "What did the root account do?", "Why is the pod crash-looping?"). The model gets the detected format, findings, alerts, offenders and statistics, never the raw log, and answers only from them. Suggested questions change with the detected format.

---

## API

**Interactive docs:** https://ai-log-analyzer-5l3n.onrender.com/swagger-ui.html

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/api/logs/upload` | Upload a log (multipart field `file`, optional `format`); max 5 MB, files over 100,000 lines are sampled |
| `GET` | `/api/logs/formats` | Formats that can be detected or forced |
| `POST` | `/api/logs/format?format=` | Re-read the loaded log with a manual format override (`auto` to detect again) |
| `GET` | `/api/logs/samples` | Bundled sample logs, one per format |
| `POST` | `/api/logs/samples/{id}` | Load a sample into your session |
| `GET` | `/api/logs/timeline?bucket=auto\|minute\|hour` | Requests and errors over time, with spike flags |
| `GET` | `/api/alerts/rules` | Active alert rules, their source file and any skipped rules |
| `GET` | `/api/logs/summary` | Findings, risk score, timeline and statistics — **no AI call, no quota used** |
| `GET` | `/api/logs/analyze` | Everything in summary plus the LLM incident report |
| `POST` | `/api/logs/chat` | Ask a question about the loaded log; JSON `{"question": "...", "history": [...]}` (shares the AI rate limit) |
| `GET` | `/api/logs/export?format=pdf\|csv\|json\|md` | PDF report with charts and AI report, findings CSV, JSON, Markdown — **no AI call** |
| `GET` | `/actuator/health` | Liveness/readiness probe (used by Render) |

Each visitor's upload is private to their browser session. Visitors who have not uploaded anything see the bundled sample log.

### Example

```bash
curl -X POST "https://ai-log-analyzer-5l3n.onrender.com/api/logs/upload" -F "file=@access.log"
curl "https://ai-log-analyzer-5l3n.onrender.com/api/logs/summary"
curl "https://ai-log-analyzer-5l3n.onrender.com/api/logs/analyze"
curl -OJ "https://ai-log-analyzer-5l3n.onrender.com/api/logs/export?format=md"
```

The analyze endpoint returns both halves:

```json
{
  "file": "sample.log",
  "summary": {
    "riskScore": 100,
    "riskLevel": "CRITICAL",
    "findings": [
      { "rule": "COMPROMISED_LOGIN", "severity": "CRITICAL", "mitre": "T1078 Valid Accounts",
        "evidence": ["203.0.113.5 logged in as admin after 9 failed attempts"], "recommendation": "..." }
    ],
    "timeline": [{ "start": "2026-11-12T03:15:00Z", "requests": 14, "errors": 12 }],
    "timelineBucketMinutes": 15
  },
  "report": "## Executive summary\n..."
}
```

---

## Supported log formats

Detected per line from the content, so mixed files work. The UI shows the detected format and has a dropdown to force one.

| Format | Recognised by | Sample |
|---|---|---|
| Apache / Nginx access | Combined log format | [`apache-access.log`](src/main/resources/samples/apache-access.log) |
| SSH auth | `sshd` lines: failed/accepted password or key, invalid user, PAM failures | [`ssh-auth.log`](src/main/resources/samples/ssh-auth.log) |
| Linux syslog | `host program[pid]: message` — sudo, su, useradd, usermod, anything else | [`linux-syslog.log`](src/main/resources/samples/linux-syslog.log) |
| JSON lines | One object per line; common keys (`remote_addr`, `client_ip`, `uri`, `status`, `level`, `@timestamp`, …) | [`json-lines.jsonl`](src/main/resources/samples/json-lines.jsonl) |
| Spring Boot / Java | `timestamp LEVEL …` (Boot and Logback), stack traces folded into their log line | [`spring-boot.log`](src/main/resources/samples/spring-boot.log) |
| Windows Security events | `EventID=` key/value, Event Viewer CSV text, or winlogbeat JSON | [`windows-security.log`](src/main/resources/samples/windows-security.log) |
| AWS CloudTrail | A `{"Records": [...]}` file or one event per line | [`cloudtrail.json`](src/main/resources/samples/cloudtrail.json) |
| UFW / iptables | Kernel lines with `SRC=` `DST=` `DPT=` | [`ufw-firewall.log`](src/main/resources/samples/ufw-firewall.log) |
| Docker / Kubernetes | kubectl events, kubelet/kernel OOM lines, Docker `json-file` logs | [`kubernetes.log`](src/main/resources/samples/kubernetes.log) |
| Anything else | Kept as text with the first IPv4 address and any timestamp | |

Unrecognised or malformed lines are never dropped and never fail the upload. Uploads are capped at 5 MB; a file longer than 100,000 lines is analysed on its first 100,000 lines and the response says so (`sampled: true`). All sample addresses use documentation ranges.

---

## Tech stack

| Layer | Choice |
|---|---|
| Language | Java 21 |
| Framework | Spring Boot 3.3.5 |
| AI | Spring AI 1.0.0 |
| Model | Google Gemini `gemini-3.6-flash` (free tier) |
| Storage | In-memory (`LogStore`) |
| Build | Maven, multi-stage Docker with cached dependencies |
| Hosting | Render (free Docker web service) |

**Operational:** `/actuator/health` for Render health checks and uptime pingers, Swagger UI for API exploration, and Bucket4j rate limiting (10 analyses/minute per IP) so a script cannot drain the free Gemini quota.

**No paid dependency.** No database, no paid SDK, no credit card.

---

## Running locally

```bash
# 1. Free Gemini key: https://aistudio.google.com/apikey
export AI_API_KEY=your-key            # Windows: set AI_API_KEY=your-key

# 2. Run
./mvnw spring-boot:run
```

Open http://localhost:8080. A sample log is loaded automatically.

### Configuration

```properties
spring.ai.openai.base-url=https://generativelanguage.googleapis.com/v1beta/openai
spring.ai.openai.api-key=${AI_API_KEY:unset}
spring.ai.openai.chat.completions-path=/chat/completions
spring.ai.openai.chat.options.model=gemini-3.6-flash
```

Environment variables:

| Variable | Default | Purpose |
|---|---|---|
| `AI_API_KEY` | `unset` | Gemini API key. Analysis returns an error until it is set. |
| `PORT` | `8080` | HTTP port (Render sets this). |
| `JAVA_OPTS` | `-XX:MaxRAMPercentage=75 -XX:+ExitOnOutOfMemoryError` | JVM flags for the container. |

> Gemini is reached through its **OpenAI-compatible** surface, so the standard Spring AI OpenAI client is used unchanged. Note there is **no `/v1`** in its paths, unlike OpenAI.

---

## Testing

```bash
./mvnw test
```

**179 tests**, covering the detection pipeline, the report features and the production hardening:

| Test class | Covers |
|---|---|
| `LogParserTest` | Apache combined and SSH auth formats, unrecognised lines, empty input |
| `LogAnalysisServiceTest` | Brute-force threshold, injection/scanner paths, 5xx clustering, traffic concentration, clean traffic, status bucketing |
| `LogParserFormatsTest` | Apache timestamps and UTC offsets, syslog year inference, account extraction, JSON lines (ISO, epoch, string status), malformed JSON fallback |
| `FindingDetectorTest` | Every rule and its thresholds, severity escalation, no false positive on clean or steady traffic, risk-score cap and bands, sort order, untrusted evidence is bounded and printable |
| `TimelineTest` | Bucketing, gap filling, bucket size scaling with the time span, no timestamps means no timeline |
| `ReportExporterTest` | Markdown content, clean-log message, log text cannot inject HTML or break tables, JSON export is valid |
| `FeatureIntegrationTest` | Sample log yields the headline findings and a timeline, `.md` and `.json` downloads with fixed filenames, bad format returns 400, exports use the caller's own upload |
| `ChatPromptTest` | Chat answers are grounded in the summary, only recent history is sent, long or empty input is clipped or skipped |
| `ChatEndpointIntegrationTest` | Empty, oversized and non-JSON questions are rejected before any AI call |
| `LogFormatDetectionTest` | Every format detected from content, with its fields (users, addresses, event ids, ports, exception classes) |
| `BoundedParsingTest` | Sampling of long files, malformed lines never fail, forced format override |
| `PlatformRulesTest` | Windows, Linux, CloudTrail, firewall, Java and container rules and their thresholds |
| `MitreMappingTest` | Every ATT&CK entry is well formed; availability rules have none |
| `SampleFilesTest` | Each bundled sample is detected as its format and produces its expected findings |
| `FormatsAndSamplesIntegrationTest` | Sample and format endpoints, per-session override, sampling of a 100,050-line upload |
| `TimelineTest` | Error breakdown by type, spike flags, per-minute and per-hour buckets, the per-minute limit |
| `IpProfilerTest` / `IpClassifierTest` | Per-address scores and reasons, GeoIP only for public addresses, host names never resolved |
| `GeoIpServiceTest` | Offline lookups against a generated test database; missing or corrupt database switches GeoIP off |
| `AlertEngineTest` / `AlertRuleTest` / `AlertRuleLoaderTest` | Sliding windows (the "more than 5 failed logins in 1 minute" example), grouping, summary rules, validation, YAML and JSON files, safe YAML |
| `AnalysisIntegrationTest` | Timeline, alert-rule and chart-library endpoints; alerts on every sample; GeoIP in the summary |
| `PdfReportTest` / `ExportIntegrationTest` | PDF text (stats, findings, charts, AI report), non-Latin and control characters, every sample renders; CSV, JSON and Markdown downloads; cached AI report reused |
| `ReportCacheTest` | AI report reused only for the same log and visitor; bounded |
| `RateLimitFilterTest` | Per-client and global limits, forged `X-Forwarded-For` cannot evade the limit, upload limit |
| `LogStoreTest` | Uploads isolated per session, sample fallback, bounded memory |
| `SessionIsolationIntegrationTest` | One visitor's upload is never visible to another; health endpoint and security headers |
| `SecurityHeadersFilterTest` | CSP, framing, nosniff, HSTS only over HTTPS |
| `GlobalExceptionHandlerTest` | Provider error text is never returned to the client |

The rule tests matter most: detection is the product here, and a rule that silently stops firing is invisible without them.

---

## Deploying to Render

1. Push this repo to GitHub
2. Render → **New → Web Service** → connect the repo
3. Runtime: **Docker**
4. Environment variable: `AI_API_KEY` = your Gemini key
5. Settings → **Health Check Path**: `/actuator/health`
6. Deploy

The `Dockerfile` caches Maven dependencies in a layer, so only your changed source recompiles on later builds. It builds through a Google-hosted Maven Central mirror with retries (Maven Central rate-limits Render's shared build IPs with HTTP 429), runs as a non-root user, and has a container `HEALTHCHECK`.

### Production notes

- **Rate limiting:** `/api/logs/analyze` is limited per client and globally (60 per minute across everyone), so the free Gemini quota cannot be drained. `/api/logs/upload` is limited per client. The client address is the last `X-Forwarded-For` entry, because Render appends the real address and does not remove values a caller sends.
- **Privacy:** uploads live in memory under the visitor's session and expire after 30 minutes. Only the four most recently used uploads are kept, and a file may have at most 100,000 lines.
- **Errors:** provider error text is logged on the server and never returned to the browser.
- **Headers:** responses carry a Content-Security-Policy, `X-Frame-Options: DENY`, `nosniff`, a referrer policy and HSTS over HTTPS.

---

## Known limitations

- **In-memory storage.** The loaded log is lost when the container restarts or sleeps. The bundled sample log is reloaded on every boot, so the demo always works.
- **Free-tier cold start.** Render sleeps after ~15 minutes idle; the first request afterwards can take up to a minute.
- **No authentication.** Public endpoint. Uploads are private per session, but do not upload confidential production logs to a shared demo.
- **Detection is rule-based, not adaptive.** The LLM explains findings; it does not discover new attack classes.
- **Time-based features need timestamps.** Logs without readable times still get every other rule, but no timeline and no burst detection.
- **Rate limiting is per-instance.** Buckets live in memory; multiple instances would need Redis.
- **Sample data is synthetic.** IPs use documentation ranges (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`).

---

## Licence

All rights reserved. The source is available for viewing only; see [LICENSE](LICENSE).
