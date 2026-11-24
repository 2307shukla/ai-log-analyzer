# ---------- build stage ----------
FROM maven:3.9-eclipse-temurin-21 AS build
WORKDIR /app

# repo.maven.apache.org rate-limits (HTTP 429) Render's shared build IPs, which fails the
# whole deploy while resolving the parent POM. maven-settings.xml mirrors Maven Central
# through Google's GCS-backed mirror (same artifacts, no such limit); the retry loops cover
# any other transient failure and still fail the build with exit 1 if every attempt fails.
COPY pom.xml maven-settings.xml ./
RUN set -e; \
    for i in 1 2 3 4 5; do \
      mvn -B -q -s maven-settings.xml dependency:go-offline && exit 0; \
      echo "Dependency resolution failed, retrying in 20s ($i/5)..."; \
      sleep 20; \
    done; \
    echo "Dependency resolution failed after 5 attempts"; exit 1

# Source last: only this layer re-runs when code changes.
COPY src ./src
RUN set -e; \
    for i in 1 2 3 4 5; do \
      mvn -B -q -s maven-settings.xml clean package -DskipTests && exit 0; \
      echo "Build failed, retrying in 20s ($i/5)..."; \
      sleep 20; \
    done; \
    echo "Build failed after 5 attempts"; exit 1

# ---------- GeoIP data: free DB-IP Lite database (CC BY 4.0), optional ----------
# Downloaded at build time so the image works offline. If the download fails the image is still
# built and GeoIP is skipped at runtime. GEOIP_EDITION=country makes a smaller image (no cities);
# GEOIP_EDITION=none skips GeoIP entirely.
FROM alpine:3.20 AS geoip
ARG GEOIP_EDITION=city
RUN mkdir -p /geoip && cd /geoip && \
    if [ "$GEOIP_EDITION" != "none" ]; then \
      for m in $(date -u +%Y-%m) $(date -u -d "@$(( $(date +%s) - 2678400 ))" +%Y-%m); do \
        url="https://download.db-ip.com/free/dbip-${GEOIP_EDITION}-lite-${m}.mmdb.gz"; \
        if wget -q -T 120 -O db.gz "$url" && gunzip -c db.gz > dbip-lite.mmdb; then \
          echo "GeoIP: using $url"; rm -f db.gz; break; \
        fi; \
        echo "GeoIP: $url not available"; rm -f db.gz dbip-lite.mmdb; \
      done; \
    fi; \
    ls -la /geoip

# ---------- runtime stage: JRE only, non-root ----------
FROM eclipse-temurin:21-jre-alpine
RUN addgroup -S app && adduser -S app -G app
WORKDIR /app
COPY --from=build /app/target/ai-log-analyzer-0.0.1-SNAPSHOT.jar app.jar
COPY --from=geoip /geoip /app/geoip
USER app
ENV PORT=8080 \
    GEOIP_DATABASE=/app/geoip/dbip-lite.mmdb \
    JAVA_OPTS="-XX:MaxRAMPercentage=75 -XX:+ExitOnOutOfMemoryError"
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=120s --retries=3 \
  CMD wget -qO- "http://localhost:${PORT}/actuator/health" >/dev/null || exit 1
ENTRYPOINT ["sh", "-c", "exec java $JAVA_OPTS -jar app.jar"]
