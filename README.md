# exitmap DNS Health - Deployment

Deployment automation for Tor exit relay DNS health validation.

**Live:** https://exitdnshealth.1aeo.com (or https://exitmap-dns.pages.dev)
**Code:** https://github.com/1aeo/exitmap

---

## Quick Start

```bash
# Clone repos
git clone https://github.com/1aeo/exitmap.git ~/exitmap
git clone https://github.com/1aeo/exitmap-dns-health-deploy.git ~/exitmap-dns-health-deploy
cd ~/exitmap-dns-health-deploy

# Configure
cp config.env.example config.env
chmod 600 config.env
nano config.env

# Install
./scripts/install.sh
```

---

## Hosting Options

### Option 1: Cloudflare Pages (Default)

Static frontend on Pages, JSON data on DO Spaces/R2.

**Required in config.env:**

```bash
CLOUDFLARE_ACCOUNT_ID=xxx
CLOUDFLARE_API_TOKEN=xxx
DO_SPACES_KEY=xxx          # Primary storage
DO_SPACES_SECRET=xxx
R2_ACCESS_KEY_ID=xxx       # Backup storage
R2_SECRET_ACCESS_KEY=xxx
```

**Deploy:**

```bash
./scripts/pages-deploy.sh
```

### Option 2: Self-hosted

```bash
# config.env
DEPLOY_IP=1.2.3.4
DEPLOY_DOMAIN=exitdns.example.com
DEPLOY_EMAIL=admin@example.com

# Install with Caddy
sudo ./scripts/install.sh --caddy
```

---

## Automation

| Schedule    | Task                             |
|-------------|----------------------------------|
| Every 6h    | Run DNS validation, upload to cloud |
| Monthly 1st | Compress data >180 days old      |

**Resolver stats (optional):** with `CF_ANALYTICS_TOKEN` and `CF_ZONE_ID` set, each scan pulls the validator
zone's sampled Cloudflare DNS analytics and adds per-exit `resolver` estimates plus `metadata.resolvers`
(version 2) via `scripts/resolver_stats.py`. Failures only log "Resolver stats skipped".

Version 2 categories are the public providers `google`, `cloudflare`, `quad9`, `opendns` and `ffmuc`,
then `local_24` (same IPv4 /24 or IPv6 /64 as the exit, including its own address), `local_22`
(same IPv4 /22 or IPv6 /48, outside that tighter prefix), `local_as` (same origin AS, outside those
prefixes), `local_operator` (same operator, outside the exit's prefix and AS), plus `other` and
`unknown`. `local_operator` uses the Onionoo effective family, a validated AROI domain, and — only
when that domain is missing — an identical ContactInfo string. `operator_signals` counts this
scan's new estimated queries that matched by address, prefix, or forward-confirmed reverse DNS
(not decayed, not weighted). Sampled rows are archived locally under `data/resolver_rows/`
(gitignored, not uploaded).

---

## Commands

```bash
# Run DNS validation scan
./scripts/run-dns-validation.sh

# Upload to cloud storage
./scripts/upload-do.sh      # DigitalOcean Spaces
./scripts/upload-r2.sh      # Cloudflare R2

# Deploy frontend
./scripts/pages-deploy.sh

# Compress old data (180+ days)
./scripts/compress-old-data.sh

# View logs
tail -f logs/cron.log
```

---

## Structure

```
~/exitmap/                     # Core scanning code
~/exitmap-dns-health-deploy/   # This repo
├── config.env                 # Your settings (gitignored)
├── scripts/                   # Automation
│   ├── run-dns-validation.sh  # Main scan runner
│   ├── upload-do.sh           # DO Spaces upload
│   ├── upload-r2.sh           # R2 upload
│   ├── pages-deploy.sh        # Cloudflare Pages deploy
│   └── compress-old-data.sh   # Monthly archival
├── functions/                 # Pages Function (data proxy)
├── public/                    # Dashboard + JSON results
│   ├── index.html             # Dashboard
│   ├── latest.json            # Current results
│   ├── files.json             # File manifest
│   └── archives/              # Compressed old data
└── logs/                      # cron.log
```

---

## Cache TTL

| File                      | TTL                |
|---------------------------|--------------------|
| latest.json, files.json   | 60s                |
| dns_health_*.json         | 1 year (immutable) |
| archives/*.tar.gz         | 1 year (immutable) |

The Pages Function caches proxied JSON under a key that includes `CACHE_KEY_VERSION`
(default `1`, set in `config.env` and written into the Pages vars by `pages-deploy.sh`).
Bump it after rewriting historical `dns_health_*.json` files so edges fetch the new
copies. `latest.json` and `files.json` expire in 60 seconds and do not need a bump.

---

## Archive Format

Files older than 180 days are compressed into monthly archives:

```
archives/exitmap-202501.tar.gz  # Contains all dns_health_202501*.json files
```

---

## License

Apache 2.0
