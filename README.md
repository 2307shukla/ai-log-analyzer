# AI Log Analyzer

An AI-assisted security log analyzer built with **Spring Boot 3** and **Spring AI**, running on **Google Gemini's free tier**.

Upload an Apache/Nginx access log or an SSH auth log. The app detects attack patterns deterministically, then has an LLM write a readable incident report with remediation advice.

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

All implemented locally in [`LogAnalysisService`](src/main/java/com/abhijeet/loganalyzer/service/LogAnalysisService.java):

- **Brute force** — 3+ failed authentications from one IP
- **Injection attempts** — SQL keywords, `'`, `<script`, `../`, `/etc/passwd`
- **Scanner probes** — `.env`, `.git`, `wp-login`, `phpmyadmin`, `/admin`
- **Server errors** — clustered 5xx responses
- **Traffic concentration** — one IP producing a third of all requests

---

## API

**Interactive docs:** https://ai-log-analyzer-5l3n.onrender.com/swagger-ui.html

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/api/logs/upload` | Upload a log (multipart field `file`) |
| `GET` | `/api/logs/summary` | Statistics only — **no AI call, no quota used** |
| `GET` | `/api/logs/analyze` | Statistics plus the LLM report |

### Example

```bash
curl -X POST "https://ai-log-analyzer-5l3n.onrender.com/api/logs/upload" -F "file=@access.log"
curl "https://ai-log-analyzer-5l3n.onrender.com/api/logs/summary"
curl "https://ai-log-analyzer-5l3n.onrender.com/api/logs/analyze"
```

The analyze endpoint returns both halves:

```json
{
  "file": "sample.log",
  "summary": { "totalLines": 56, "signals": ["Brute-force pattern: 9 failed authentications from 203.0.113.5"] },
  "report": "## Executive summary\n..."
}
```

---

## Supported log formats

- **Apache / Nginx combined** — `IP - - [date] "METHOD path HTTP/1.1" status bytes "referer" "ua"`
- **SSH auth logs** — lines containing `Failed password`, `Invalid user`, `authentication failure`

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

> Gemini is reached through its **OpenAI-compatible** surface, so the standard Spring AI OpenAI client is used unchanged. Note there is **no `/v1`** in its paths, unlike OpenAI.

---

## Deploying to Render

1. Push this repo to GitHub
2. Render → **New → Web Service** → connect the repo
3. Runtime: **Docker**
4. Environment variable: `AI_API_KEY` = your Gemini key
5. Deploy

The `Dockerfile` caches Maven dependencies in a layer, so only your changed source recompiles on later builds.

---

## Known limitations

- **In-memory storage.** The loaded log is lost when the container restarts or sleeps. The bundled sample log is reloaded on every boot, so the demo always works.
- **Free-tier cold start.** Render sleeps after ~15 minutes idle; the first request afterwards can take up to a minute.
- **No authentication.** Public endpoint — do not upload confidential production logs.
- **Detection is rule-based, not adaptive.** The LLM explains findings; it does not discover new attack classes.
- **Rate limiting is per-instance.** Buckets live in memory; multiple instances would need Redis.
- **Sample data is synthetic.** IPs use documentation ranges (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`).

---

## Licence

MIT
