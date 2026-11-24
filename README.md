# AI Log Analyzer

An AI-assisted security log analyzer built with **Spring Boot 3** and **Spring AI**, running on **Google Gemini's free tier**.

Upload an Apache/Nginx access log, an SSH auth log, or JSON-lines logs. The app detects attack patterns deterministically, scores the risk, maps each finding to **MITRE ATT&CK**, draws a request timeline, then has an LLM write a readable incident report. Reports can be downloaded as Markdown or JSON.

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

All implemented locally in [`FindingDetector`](src/main/java/com/abhijeet/loganalyzer/service/FindingDetector.java). Every finding carries a severity, a MITRE ATT&CK technique where one applies, a count, up to five pieces of evidence, and a concrete recommendation.

| Rule | Severity | MITRE ATT&CK | Fires when |
|---|---|---|---|
| `COMPROMISED_LOGIN` | CRITICAL | T1078 Valid Accounts | An address logs in successfully after 3+ failures |
| `BRUTE_FORCE` | MEDIUM / HIGH / CRITICAL | T1110 Brute Force | 3+ failed logins from one address (HIGH at 10, CRITICAL at 50) |
| `PASSWORD_SPRAYING` | HIGH | T1110.003 Password Spraying | One address tries 5+ different account names |
| `SQL_INJECTION` | HIGH | T1190 Exploit Public-Facing Application | SQL syntax in the URL, including URL-encoded forms |
| `PATH_TRAVERSAL` | HIGH | T1190 | `../`, `/etc/passwd` and similar in the URL |
| `XSS` | MEDIUM | T1190 | Script or event-handler payloads in the URL |
| `SENSITIVE_PATH_PROBING` | MEDIUM / HIGH | T1595.003 Wordlist Scanning | Requests for `.env`, `.git`, `wp-login`, `phpmyadmin`, admin panels (HIGH when one address makes 10+) |
| `SCANNER_USER_AGENT` | MEDIUM | T1595.002 Vulnerability Scanning | Known scanner user agents such as sqlmap or nikto |
| `FORCED_BROWSING` | MEDIUM | T1595.003 | One address hits 10+ different pages that return 404 |
| `SERVER_ERRORS` | MEDIUM / HIGH | | 3+ responses with a 5xx status (HIGH at 20) |
| `REQUEST_BURST` | MEDIUM / HIGH | T1498 Network Denial of Service | Busiest minute is at least 5x the median and at least 20 requests; needs timestamps and 30+ timed events |
| `TRAFFIC_CONCENTRATION` | LOW | | One address produces a third of all requests |

**Risk score.** Each finding adds its severity weight (CRITICAL 40, HIGH 25, MEDIUM 12, LOW 4), capped at 100. The overall level is the higher of the score band (70+ CRITICAL, 40+ HIGH, 15+ MEDIUM, otherwise LOW) and the most serious single finding, so one critical issue is never hidden behind a low total. A log with no findings is `CLEAN`.

Everything that came from the log is untrusted text. Evidence is clipped, stripped of control characters, and escaped wherever it is rendered (dashboard and Markdown export).

---

## API

**Interactive docs:** https://ai-log-analyzer-5l3n.onrender.com/swagger-ui.html

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/api/logs/upload` | Upload a log (multipart field `file`) |
| `GET` | `/api/logs/summary` | Findings, risk score, timeline and statistics — **no AI call, no quota used** |
| `GET` | `/api/logs/analyze` | Everything in summary plus the LLM incident report |
| `GET` | `/api/logs/export?format=md\|json` | Downloadable report built from the findings — **no AI call** |
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

- **Apache / Nginx combined** — `IP - - [date] "METHOD path HTTP/1.1" status bytes "referer" "ua"`; the timestamp and its UTC offset are read
- **SSH auth logs** — `Failed password`, `Accepted password/publickey`, `Invalid user`, `authentication failure`; the account name is extracted, and the year (syslog omits it) is taken from other dated lines in the file or the current year
- **JSON lines** — one object per line, with common key names for address, path, status, user agent and time (ISO-8601 or epoch), so Nginx/Caddy/app JSON logs work as they are

Unrecognised lines are never dropped — they are kept with their raw text and any IP found, so the parser degrades instead of failing.

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

**66 tests**, covering the detection pipeline, the report features and the production hardening:

| Test class | Covers |
|---|---|
| `LogParserTest` | Apache combined and SSH auth formats, unrecognised lines, empty input |
| `LogAnalysisServiceTest` | Brute-force threshold, injection/scanner paths, 5xx clustering, traffic concentration, clean traffic, status bucketing |
| `LogParserFormatsTest` | Apache timestamps and UTC offsets, syslog year inference, account extraction, JSON lines (ISO, epoch, string status), malformed JSON fallback |
| `FindingDetectorTest` | Every rule and its thresholds, severity escalation, no false positive on clean or steady traffic, risk-score cap and bands, sort order, untrusted evidence is bounded and printable |
| `TimelineTest` | Bucketing, gap filling, bucket size scaling with the time span, no timestamps means no timeline |
| `ReportExporterTest` | Markdown content, clean-log message, log text cannot inject HTML or break tables, JSON export is valid |
| `FeatureIntegrationTest` | Sample log yields the headline findings and a timeline, `.md` and `.json` downloads with fixed filenames, bad format returns 400, exports use the caller's own upload |
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
