# NRPI Subdomain Host — operator guide

This box (`corpitpen`, 10.9.58.207) hosts department subdomains under
`*.nrpi.local` (e.g. `hr.nrpi.local`, `accessportal.nrpi.local`). It was wiped
of its previous pentest-engine role on 2026-08-24.

## What runs here

| Piece | Location |
|-------|----------|
| Admin console (Flask) | `/opt/subdomain-admin/` — gunicorn on 127.0.0.1:5000, unit `subdomain-admin.service` |
| Parked "coming soon" page | `/var/www/parked/index.html` (shared by every new subdomain) |
| Provisioning helper (root) | `/usr/local/sbin/nrpi-subdomain` (create \| remove \| list) |
| Restricted sudo rule | `/etc/sudoers.d/subdomain-admin` — lets the app run only the helper |
| Per-subdomain vhosts | `/etc/nginx/sites-available/sub-<label>` → symlinked in sites-enabled |
| Per-subdomain certs | `/etc/ssl/subdomains/<fqdn>/` (self-signed + CSR) |
| Admin/default cert | `/etc/ssl/subadmin/` (self-signed) |
| Default server (unknown hosts) | `/etc/nginx/sites-available/00-default` → returns 404 |
| Admin vhost | `/etc/nginx/sites-available/01-subdomain-admin` |

Firewall (UFW): only 22 (SSH) and 443 (HTTPS) are open.

## Admin console

Reach it at **https://10.9.58.207/** now (self-signed cert → browser warning is
expected). Once DNS is added it will also answer at **https://subadmin.nrpi.local/**.

- Login: user `admin`. The initial password was generated at setup.
- **Change your password in the browser:** click `admin` (top-right) → the
  Account page. Change takes effect immediately (no restart).
- SSH fallback for a forgotten password:
  ```
  cd /opt/subdomain-admin && ./venv/bin/python setpw.py admin
  sudo systemctl restart subdomain-admin
  ```

## Creating a subdomain

In the console: **Request a new subdomain** → enter the label (e.g. `hr`) →
Create. That instantly:
1. generates a self-signed cert **and** a CSR for NRPI-CA,
2. writes + enables an nginx vhost serving the parked page,
3. reloads nginx and waits until the site actually answers.

The subdomain is then reachable on this host over the parked page. It is **not**
yet resolvable by name or trusted until you finish go-live.

## Finishing go-live (per subdomain — done off this box)

1. **DNS** — add an A record in the `nrpi.local` forest zone:
   `hr.nrpi.local.  IN A  10.9.58.207`
2. **Certificate** — submit the CSR at
   `/etc/ssl/subdomains/<fqdn>/server.csr` to **NRPI-CA**, save the signed cert
   over `/etc/ssl/subdomains/<fqdn>/server.crt`, then `sudo systemctl reload nginx`.
3. **Publish the real site** — edit `/etc/nginx/sites-available/sub-<label>` and
   replace the parked `root` block with the real content root or a `proxy_pass`
   to the department's app, then reload nginx.

## Pentest-engine decommission (historical)

This box previously ran a pentest engine. It was wiped on 2026-08-24; the final
remnants — the `pentest-scheduler` systemd timer/service and the 27 MB backup
archive at `/home/ubuntu/pentest-engine-backup-20260824-235518/` — were removed
on 2026-09-01. No pentest-engine components or rollback archive remain on this host.

## Handy commands

```
sudo -n /usr/local/sbin/nrpi-subdomain list        # what's provisioned
sudo systemctl status subdomain-admin nginx         # service health
sudo tail -f /var/log/nginx/error.log               # nginx errors
```
