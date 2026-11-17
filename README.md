# Sixy

A self-hosted dashboard that checks what your home network exposes to the internet.

- **Where the scan comes from:** always from outside your network. Scanning your own WAN IP from inside your LAN gives misleading results because of NAT loopback. There are two engines to choose from (Settings → Scan engine):
  - **Google Cloud Run** (default): nmap runs as a Cloud Run job in your Google project. Sixy creates the job for you from a service-account key you upload, and the free tier covers hourly scans of the top 1,000 ports. TCP only.
  - **Local, through a VPN:** nmap runs inside the Sixy container, which shares the network of a [gluetun](https://github.com/qdm12/gluetun) VPN container you provide, so the probes leave through your VPN. It supports SYN and UDP scans and any port range, and needs no cloud account. See [Local engine through a VPN](#local-engine-through-a-vpn-gluetun-sidecar).
- **Dynamic IP:** the container looks up your current WAN IP before each scan.
- **What it reports:** each open port's nmap fingerprint (service and version), a plain-English guess at what it is, a risk rating, and Shodan's InternetDB view of your IP (indexed ports and CVEs).
- **Alerts:** sent through Apprise (ntfy, Telegram, Discord, email…) when ports open or close, your IP changes, Shodan lists new CVEs, or a scan fails.
- **Monitoring endpoint:** `/healthz` returns 200 when the last scan was clean and 503 when there are unexpected ports, the scan failed, or results are stale. You can point Uptime Kuma at it.

## How it works (Cloud Run engine)

```
[sixy container @ home] --(service-account key)--> Cloud Run Admin API: run job with args "nmap ... <your WAN IP>"
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
# open http://<host>:8080 and sign in with ADMIN_PASSWORD
```

Or run it without compose:

```bash
docker run -d --name sixy -p 8080:8080 -e ADMIN_PASSWORD=change-me \
  -v sixy-data:/data ghcr.io/asward/sixy:latest
```

To preview the dashboard without a Google account, set `SCAN_BACKEND=demo`.

**Login**
- **Signing in:** the dashboard has a sign-in page that asks only for `ADMIN_PASSWORD`. Sessions last 30 days and survive container restarts.
- **Scripts and curl:** HTTP basic auth still works, e.g. `curl -u :PASSWORD http://host:8080/api/status`.
- **No password:** if `ADMIN_PASSWORD` is unset, the UI is open to anyone who can reach it.
- **`$` in Compose:** Compose treats `$` as the start of a variable, so write `$$` for a literal `$` in the password.
- **Checking the password:** the container log prints the password's length at startup, so you can confirm what it actually received.
- **Monitoring:** `/healthz` (scan status) and `/livez` (process alive) work without logging in.

## Development

| Script | What it does |
|---|---|
| `scripts/test.sh` | Creates `.venv`, installs dev dependencies, runs pytest (extra args are passed through) |
| `scripts/build.sh` | `docker build` → `sixy:local`. Set `IMAGE=` to change the tag; set `PLATFORMS=linux/amd64,linux/arm64 PUSH=1` for a multi-arch buildx push |
| `scripts/run-demo.sh` | Builds the image and runs it in demo mode on :8080 |

**CI (GitHub Actions)**
- `tests.yml`: runs on pushes to other branches and on PRs.
  - Runs pytest on Python 3.12 and 3.13, including a real nmap scan of a local listener.
  - Runs a container smoke test: it signs in, completes a demo scan, then runs a real local-engine scan *inside* the container as the non-root user, which proves the raw-socket capability works.
- `docker-publish.yml`: runs on pushes to `main` and on `v*.*.*` tags. It runs the tests first, then builds a multi-arch image and pushes it to GHCR.
  - Tags from `main`: `latest` and `sha-<short>`.
  - Tags from a release tag: `1.2.3` and `1.2`.

GHCR packages start out private. To pull without logging in, make the package public under GitHub → your profile → Packages → sixy → Package settings.

## Local engine through a VPN (gluetun sidecar)

Sixy doesn't bundle a VPN. You run [gluetun](https://github.com/qdm12/gluetun) with your own VPN provider or WireGuard config, and Sixy joins its network namespace. Every packet Sixy sends (scans, IP lookups, Shodan, notifications) then goes through the VPN. If the VPN drops, gluetun's built-in firewall blocks all traffic, so a scan can never quietly run from inside your LAN.

```yaml
services:
  gluetun:
    image: qmcgaw/gluetun:latest
    container_name: gluetun
    cap_add: [NET_ADMIN]
    devices: [/dev/net/tun:/dev/net/tun]
    ports:
      - "8080:8080"                 # Sixy's UI is published on the gluetun container
    environment:
      VPN_SERVICE_PROVIDER: mullvad   # or protonvpn, airvpn, custom, ... (see gluetun wiki)
      VPN_TYPE: wireguard
      WIREGUARD_PRIVATE_KEY: "..."
      WIREGUARD_ADDRESSES: "10.64.0.2/32"
      SERVER_CITIES: "Seattle WA"     # any exit far from home is fine
      FIREWALL_INPUT_PORTS: "8080"    # let your LAN reach Sixy's UI through gluetun's firewall
      # FIREWALL_OUTBOUND_SUBNETS: "192.168.1.0/24"  # only if the WAN IP lookup URL is on your LAN
    restart: unless-stopped

  sixy:
    image: ghcr.io/asward/sixy:latest
    container_name: sixy
    network_mode: "service:gluetun"   # share gluetun's network; no `ports:` here
    depends_on:
      gluetun:
        condition: service_healthy
    environment:
      ADMIN_PASSWORD: "change-me"
      TZ: America/Los_Angeles
    volumes:
      - sixy-data:/data
    restart: unless-stopped

volumes:
  sixy-data:
```

Then in Sixy:

1. **Settings → Scan engine:** choose **Local, through a VPN container**.
2. **Target:** set your **DDNS hostname** (e.g. `myhome.duckdns.org`). Inside the VPN, "what's my IP" returns the VPN server's address, not your home's. The alternative is a **WAN IP lookup URL** that bypasses the tunnel: a LAN service that returns your home IP as plain text, allowed through gluetun with `FIREWALL_OUTBOUND_SUBNETS`.
3. **UDP ports:** adjust the list if needed. The defaults are the commonly abused services: DNS, NTP, SNMP, SSDP, memcached, and so on.

**Safety check before every scan:** Sixy compares the IP its own traffic leaves from with the target IP. If they match, it refuses to scan and tells you why. A match means either Sixy isn't behind the VPN (a hairpin scan from inside your network) or the "home" IP it detected is actually the VPN's.

**Notes**
- **Raw sockets:** nmap in the image has the `cap_net_raw` file capability, so the container stays non-root and still runs SYN and UDP scans. Docker grants `NET_RAW` to containers by default.
  - Don't add `security_opt: [no-new-privileges:true]` or `cap_drop: [ALL]` to the Sixy service, because either one disables the capability.
  - If raw sockets are unavailable anyway, Sixy falls back to a TCP connect scan, skips UDP, and logs an event saying so.
- **UDP results:** only ports that send a reply count as open. A UDP port with no reply looks the same as a firewalled one. **WireGuard never replies to unauthenticated packets, so no scanner can see it.** That's by design.
- **Provider terms of service:** many commercial VPN providers forbid port scanning. Scanning your own single IP is low-volume, but check your provider's terms, or use your own WireGuard server on a VPS (gluetun's `VPN_SERVICE_PROVIDER: custom`).
- **Restarts:** if gluetun restarts, restart Sixy too. A container that shares another's network loses it when that container is recreated.

## Google Cloud setup (Cloud Run engine)

The Settings page walks you through this, including a Cloud Shell snippet to paste. In summary:

1. Create a project and link billing. Cloud Run requires billing, but this usage stays within the free tier. Adding a $1 budget alert is recommended.
2. Run the snippet. It enables the Cloud Run and Logging APIs, creates a `sixy-scanner` service account, grants it the roles below, and downloads a JSON key.
   - `roles/run.developer`: create, update and run the job
   - `roles/logging.viewer`: read the nmap output
   - `roles/logging.logWriter`
   - `roles/iam.serviceAccountUser` on itself: the job runs as the same service account
3. In the dashboard, upload the key, click **Deploy**, set your allowed ports, turn on the schedule, and click **Scan now**.

> If your Google account belongs to a Workspace organization, the org policy
> `iam.disableServiceAccountKeyCreation` may block key creation. Personal Gmail accounts aren't affected.

## Free-tier math (Cloud Run engine)

Cloud Run Jobs include 240k vCPU-seconds per month for free (Tier-1 regions).

| Profile | Approx. time per scan | Hourly (720 scans/mo) | Daily (30 scans/mo) |
|---|---|---|---|
| Top 100 | ~20–40 s | ~25k vCPU-s ✅ | ✅ |
| Top 1000 + `-sV` | ~60–120 s | ~45–90k ✅ | ✅ |
| All 65,535 | 5–20 min | ❌ exceeds free tier | ✅ |

## Limitations

- **The Cloud Run engine is TCP only.** It runs a TCP connect scan (`-sT`) with the stock nmap image. Use the local/VPN engine for UDP. WireGuard stays invisible either way, by design.
- **IPv4 only.** Devices reachable over IPv6 aren't scanned.
- **CGNAT.** If your ISP puts you behind CGNAT, the IP the container detects belongs to the ISP's shared gateway, not to you. In that case nothing reaches you inbound anyway.
- **Running outside your home network.** If the container doesn't run at home, set **Target** to your DDNS hostname.
- **Port descriptions are educated guesses.** The "Likely service" text is based on well-known port numbers. nmap's fingerprint column is the stronger evidence.
