# WAN Watch

A self-hosted dashboard that checks what your home network exposes to the internet.

- **Where the scan comes from:** nmap runs in **Google Cloud Run**, so the scan reaches your network from the outside. Scanning your own WAN IP from inside your LAN gives misleading results because of NAT loopback.
- **Cost:** the free tier covers hourly scans of the top 1,000 ports.
- **Setup:** the container creates the Cloud Run job in your Google project for you, using a service-account key you upload.
- **Dynamic IP:** the container looks up your current WAN IP before each scan.
- **What it reports:** each open port's nmap fingerprint (service and version), a plain-English guess at what it is, a risk rating, and Shodan's InternetDB view of your IP (indexed ports and CVEs).
- **Alerts:** sent through Apprise (ntfy, Telegram, Discord, email…) when ports open or close, your IP changes, Shodan lists new CVEs, or a scan fails.
- **Monitoring endpoint:** `/healthz` returns 200 when the last scan was clean and 503 when there are unexpected ports, the scan failed, or results are stale. You can point Uptime Kuma at it.

## How it works

```
[wanwatch container @ home] --(service-account key)--> Cloud Run Admin API: run job with args "nmap ... <your WAN IP>"
          ^                                              |
          |                                     Cloud Run Job (public image instrumentisto/nmap)
          |                                              | scans your IP from Google's network
          +---------- Cloud Logging API <-------- stdout (nmap greppable output)
```

No public endpoint is created. The scanner only runs when your container starts it, and it only scans the IP your container passes to it.

## Run it

The prebuilt image (amd64 and arm64) is published to `ghcr.io/asward/sixy`:

```bash
docker compose up -d          # pulls ghcr.io/asward/sixy:latest
# open http://<host>:8080   (basic auth: any username, password = ADMIN_PASSWORD)
```

Or run it without compose:

```bash
docker run -d --name wanwatch -p 8080:8080 -e ADMIN_PASSWORD=change-me \
  -v wanwatch-data:/data ghcr.io/asward/sixy:latest
```

To preview the dashboard without a Google account, set `SCAN_BACKEND=demo`.

## Development

| Script | What it does |
|---|---|
| `scripts/test.sh` | Creates `.venv`, installs dev dependencies, runs pytest (extra args are passed through) |
| `scripts/build.sh` | `docker build` → `wanwatch:local`. Set `IMAGE=` to change the tag; set `PLATFORMS=linux/amd64,linux/arm64 PUSH=1` for a multi-arch buildx push |
| `scripts/run-demo.sh` | Builds the image and runs it in demo mode on :8080 |

**CI (GitHub Actions)**
- `tests.yml`: runs on pushes to other branches and on PRs. It runs pytest on Python 3.12 and 3.13, then a container smoke test that builds the image, starts it in demo mode, and checks that a scan completes.
- `docker-publish.yml`: runs on pushes to `main` and on `v*.*.*` tags. It runs the tests first, then builds a multi-arch image and pushes it to GHCR.
  - Tags from `main`: `latest` and `sha-<short>`.
  - Tags from a release tag: `1.2.3` and `1.2`.

GHCR packages start out private. To pull without logging in, make the package public under GitHub → your profile → Packages → sixy → Package settings.

## Google Cloud setup

The Settings page walks you through this, including a Cloud Shell snippet to paste. In summary:

1. Create a project and link billing. Cloud Run requires billing, but this usage stays within the free tier. Adding a $1 budget alert is recommended.
2. Run the snippet. It enables the Cloud Run and Logging APIs, creates a `wanwatch` service account, grants it the roles below, and downloads a JSON key.
   - `roles/run.developer`: create, update and run the job
   - `roles/logging.viewer`: read the nmap output
   - `roles/logging.logWriter`
   - `roles/iam.serviceAccountUser` on itself: the job runs as the same service account
3. In the dashboard, upload the key, click **Deploy**, set your allowed ports, turn on the schedule, and click **Scan now**.

> If your Google account belongs to a Workspace organization, the org policy
> `iam.disableServiceAccountKeyCreation` may block key creation. Personal Gmail accounts aren't affected.

## Free-tier math

Cloud Run Jobs include 240k vCPU-seconds per month for free (Tier-1 regions).

| Profile | Approx. time per scan | Hourly (720 scans/mo) | Daily (30 scans/mo) |
|---|---|---|---|
| Top 100 | ~20–40 s | ~25k vCPU-s ✅ | ✅ |
| Top 1000 + `-sV` | ~60–120 s | ~45–90k ✅ | ✅ |
| All 65,535 | 5–20 min | ❌ exceeds free tier | ✅ |

## Limitations

- **TCP only.** Cloud Run allows no raw sockets, so the scan is a TCP connect scan (`-sT`). UDP services such as WireGuard won't show up.
- **CGNAT.** If your ISP puts you behind CGNAT, the IP the container detects belongs to the ISP's shared gateway, not to you. In that case nothing reaches you inbound anyway.
- **Running outside your home network.** If the container doesn't run at home, set **Target override** to your DDNS hostname.
- **Port descriptions are educated guesses.** The "Likely service" text is based on well-known port numbers. nmap's fingerprint column is the stronger evidence.
