# Self-hosting the Hangar Drive server

The Hangar Drive server keeps your devices in sync and keeps every version for a retention
window that you, the operator, choose. Everything it stores is end-to-end encrypted: it sees
object sizes (padded), counts and times, but no file names, paths or contents.

This guide covers installation, the first invite, a reverse proxy with TLS, configuration,
backups, updates and the server key number.

## Requirements

- A Linux host with Docker and Docker Compose 2.24 or newer.
- A domain name pointing to the host, for TLS with a public certificate (recommended), or a
  self-signed certificate that devices pin when they pair.
- Disk space: see [Disk sizing](#disk-sizing). Retention keeps old versions, so plan for more
  than the size of your files.

## Install in five steps

1. Get the source, set the address devices will reach your server under, and build the image:

   ```sh
   git clone <repository URL> hangar-drive
   cd hangar-drive
   echo "HANGAR_DRIVE_PUBLIC_URL=https://drive.example.org/" > .env
   docker compose up -d --build
   ```

   `HANGAR_DRIVE_PUBLIC_URL` is required: without it Compose refuses to start the service
   and the server itself does not start either, with a message that says how to set it.
   Every sign-in is bound to this address ([Invite links](#invite-links)). For a first test on
   this machine alone, `http://localhost:8080/` works.

2. Check that it runs:

   ```sh
   curl http://localhost:8080/api/v1/health
   # {"version":"0.1.0","protocol_version":1}
   ```

   The port is bound to `127.0.0.1` only. Devices never talk to it directly.

3. Put a reverse proxy with TLS in front of it ([Caddy](#caddy) or [nginx](#nginx)).

4. Create the first invite (with the address of step 1 in `HANGAR_DRIVE_PUBLIC_URL`; after
   changing it, restart with `docker compose up -d`):

   ```sh
   docker compose exec server hangar-drive-server invite
   # https://drive.example.org/join#<invite>.<server ID>
   ```

   The command prints the whole invite link once. It is valid for 7 days (`--days N`, up to
   90) and creates exactly one account; the server stores only the invite's hash. Everything
   after `#` is the invite: browsers and proxies never send that part to a server, so it ends
   up in no access log. Send the whole link. With a self-signed certificate, add `--pin` (see
   [Invite links](#invite-links)).

5. Open the link on the new device. The page `/join` of your server explains that the link
   belongs to the Hangar Drive app and offers a button that opens it there; pasting the link
   into the app ("Start with an invite link") works as well. Further devices of the same
   account join by pairing from a device you already have; they need no invite.

### Invite links

The link has the form `<public URL>join#<invite>.<server ID>[.<pin>]`:

- `<invite>`: the single-use invite, 22 characters (base64url).
- `<server ID>`: the server's ID, 32 hex digits. The app checks it when it first connects, so
  a link cannot be redirected to another server.
- `<pin>`: only with `invite --pin`: the SHA-256 of the certificate's public key (SPKI), 43
  characters (base64url), taken from `HANGAR_DRIVE_TLS_CERT`, `--cert FILE` or `--spki HEX`.
  Use it only for a self-signed certificate. A certificate from a public authority (Let's
  Encrypt) needs no pin, and pinning one would lock devices out when a renewal brings a new
  key.

`HANGAR_DRIVE_PUBLIC_URL` must be an `https` address (`http` only for `localhost`), without a
user name, query or fragment; a path is allowed (`https://example.org/drive/` gives
`https://example.org/drive/join#...`). The server itself serves the page at `/join` (with
`/join.js` and `/join.css`); behind a path prefix, the reverse proxy maps it. The page loads no
third-party resource, runs only its own script under a strict Content Security Policy, and
builds the app link `hangar-drive://join#...` from the fragment in the browser.

The public URL also guards every sign-in: a device signs its session proof for the address it
connects to, and the server refuses a proof for any other address. A host that copies your
server's ID into a link or recovery sheet with its own address therefore cannot pass a device's
sign-in on to your server. That is why the server does not start without
`HANGAR_DRIVE_PUBLIC_URL`. Keep it the address your devices use: changing it signs every device
out until it is set back.

## Reverse proxy

The proxy must:

- allow request bodies of at least 5 MiB for file chunks; directory listings of very large
  folders and the commit of a large first upload need more, so allow **100 MiB**;
- pass the event stream (`/api/v1/account/events`, server-sent events) without buffering and
  keep it open: the server sends a keepalive every 25 seconds;
- append the client address to `X-Forwarded-For`, and nothing else;
- limit connections per client address and give up on slow request headers and bodies (the
  server limits connections per address too, but behind a proxy every connection comes from
  the proxy's address, which the server cannot limit without limiting everyone);
- send `Strict-Transport-Security`, so a browser or client that saw the server once never
  falls back to plain HTTP.

Then set `HANGAR_DRIVE_TRUSTED_PROXIES` to the proxy's exact address. The server uses
`X-Forwarded-For` for rate limits only, and only from connections that come from a trusted
proxy. The setting is empty by default: trust no more than the one address your proxy
connects from, never a whole private range, because every other container or process in that
range could then choose its own rate limit key. Leave access logs of the proxy off or without
request headers: the `Authorization` header carries session tokens.

If the proxy is missing from that list, every client behind it shares the proxy's address and
so its rate limits: one client can use them up for all. The server logs an `operator warning`
once per address when a private, loopback or link-local address sends `X-Forwarded-For`
without being listed; add that exact address if it is your proxy.

### Caddy

Caddy obtains and renews a Let's Encrypt certificate on its own. The commented `caddy` service in
`docker-compose.yml` uses this `Caddyfile` next to it:

```caddyfile
{
	servers {
		timeouts {
			# Slow request headers end the connection.
			read_header 10s
			idle 2m
		}
	}
}

{$DRIVE_DOMAIN} {
	request_body {
		max_size 100MB
	}
	reverse_proxy server:8080 {
		# Server-sent events: send every event at once.
		flush_interval -1
		stream_timeout 24h
	}
	header {
		Strict-Transport-Security "max-age=31536000; includeSubDomains"
		-Server
	}
}
```

Caddy has no built-in limit of connections per client address; the server's own limit
(`HANGAR_DRIVE_CONNECTIONS_PER_IP`) does not apply behind it, so put a firewall rule (for
example `iptables -m connlimit`) in front of port 443 if you expect abuse.

The `caddy` service in `docker-compose.yml` has the fixed address `172.30.250.10` on the
Compose network `drive`. Uncomment the line `HANGAR_DRIVE_TRUSTED_PROXIES: 172.30.250.10` of
the `server` service together with the `caddy` service, and nothing else.

### nginx

```nginx
# In the http block: one zone of connection counts per client address.
limit_conn_zone $binary_remote_addr zone=drive_conn:10m;

server {
    listen 443 ssl;
    http2 on;
    server_name drive.example.org;

    ssl_certificate     /etc/letsencrypt/live/drive.example.org/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/drive.example.org/privkey.pem;
    ssl_protocols       TLSv1.3;
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;

    # 5 MiB at least for chunks; 100 MiB for large directory nodes and commits.
    client_max_body_size 100m;
    # Slow clients: headers within 10 s, no pause longer than 30 s in a body.
    client_header_timeout 10s;
    client_body_timeout 30s;
    # Connections per client address (an event stream and a few requests per device).
    limit_conn drive_conn 64;
    access_log off;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_request_buffering off;
    }

    location /api/v1/account/events {
        proxy_pass http://127.0.0.1:8080;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header Connection "";
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        # Server-sent events: no buffering, and longer than the 25 s keepalive.
        proxy_buffering off;
        proxy_cache off;
        proxy_read_timeout 1h;
    }
}
```

An nginx on the host reaches the container through Docker's port mapping, so the connection
comes from the gateway of the Compose network `drive`, `172.30.250.1`. Uncomment the line
`HANGAR_DRIVE_TRUSTED_PROXIES` of the `server` service in `docker-compose.yml` and set it to
`172.30.250.1`. Every connection to the published port on the host comes from that address,
so with this setting only the proxy may reach the published port: keep it bound to
`127.0.0.1` and do not run other services on the host that connect to it.

### TLS in the server instead of a proxy

The server can terminate TLS 1.3 itself. Mount the certificate chain and key (PEM) into the
container and set `HANGAR_DRIVE_TLS_CERT` and `HANGAR_DRIVE_TLS_KEY`. Then bind the port to the
network instead of `127.0.0.1`. A reverse proxy remains the recommended setup: it renews
certificates on its own. A server that terminates TLS itself sends
`Strict-Transport-Security: max-age=31536000` on every reply; behind a proxy it sends none, so
set it in the proxy as shown above.

### Forward proxies on the devices

The app uses the forward proxy of the device's environment (`HTTPS_PROXY`, `ALL_PROXY`) for
`https` server addresses. Such a proxy only tunnels the TLS connection: it learns the server's
host name, but the app checks the certificate, or the pinned key of a self-signed server, end
to end with the server, so the proxy can neither read nor change a request. Networks that allow
`https` only through a proxy therefore keep working. Plain `http`, which the app allows only for
`localhost`, `127.0.0.1` and `::1`, never goes through a proxy: the session token would travel
through it in the clear.

## Configuration

Every setting is an environment variable. Sizes take bytes or a binary suffix (`512MiB`,
`50GiB`, `1TiB`). The server refuses to start on an invalid value and names the variable.

| Variable | Default | Meaning |
| --- | --- | --- |
| `HANGAR_DRIVE_PORT` | `8080` | Port to listen on |
| `HANGAR_DRIVE_PUBLIC_URL` | none, required | The address devices reach the server under, for the links `invite` prints and the sign-in check ([Invite links](#invite-links)); the server does not start without it |
| `HANGAR_DRIVE_DATA_DIR` | `/data` in the image | Database and objects |
| `HANGAR_DRIVE_RETENTION_DAYS` | `30` | How long a version stays restorable after it was replaced (W) |
| `HANGAR_DRIVE_RETENTION_MIN_COMMITS` | `10` | Newest versions per folder kept regardless of age, within the minimum count cap |
| `HANGAR_DRIVE_QUOTA` | `100GiB` | Live bytes per account (Q); old versions do not count |
| `HANGAR_DRIVE_HEADROOM` | 1% of Q, at least 64 MiB | Extra room for directory listings, so deleting works at a full quota (H) |
| `HANGAR_DRIVE_MIN_COUNT_CAP` | Q | Bytes that only the minimum count keeps, per account (C) |
| `HANGAR_DRIVE_ACCOUNT_BUDGET` | Q | Bytes an account may make live per 24 hours (B) |
| `HANGAR_DRIVE_DEVICE_BUDGET` | the account budget | Bytes one device may make live per 24 hours |
| `HANGAR_DRIVE_DISK_RESERVE` | `1GiB` | Below this much free disk space, uploads are refused |
| `HANGAR_DRIVE_TRUSTED_PROXIES` | empty | Comma-separated addresses of reverse proxies (CIDR ranges are accepted; prefer the exact address) |
| `HANGAR_DRIVE_RECORD_CAP` | `64MiB` | Bytes of encrypted account records (folder keys, folder list, device names) per account (R) |
| `HANGAR_DRIVE_HEAVY_REQUESTS` | `4` | Commits and record writes worked on at once; their bodies are held in memory |
| `HANGAR_DRIVE_UPLOADS_PER_ACCOUNT` | `8` | Uploads one account may have in flight at once |
| `HANGAR_DRIVE_CONNECTIONS_PER_IP` | `64` | Open connections per client address; trusted proxies are exempt |
| `HANGAR_DRIVE_TLS_CERT`, `HANGAR_DRIVE_TLS_KEY` | empty | PEM files for TLS in the server |
| `HANGAR_DRIVE_GC_INTERVAL_MINUTES` | `60` | Minutes between two garbage collection steps |
| `HANGAR_DRIVE_SHUTDOWN_GRACE_SECS` | `10` | How long a shutdown waits for open requests |
| `HANGAR_DRIVE_ANOMALY_MIN_OBJECTS` | `500` | Replaced or dropped file objects within an hour that always count as a burst; a smaller folder needs `HANGAR_DRIVE_ANOMALY_PERCENT` of its file objects, at least 20 |
| `HANGAR_DRIVE_ANOMALY_PERCENT` | `30` | Share of a folder's data (and of its file objects) a burst must replace or drop; retiring a folder counts as dropping all of it |
| `RUST_LOG` | `info` | Log level |

### What the limits protect against

A device that is compromised (for example by ransomware) can rewrite or delete your files. It
cannot delete old versions: no client call deletes anything, and old versions stay for the
retention window. A burst of replaced or dropped files pins the last version before it for 90
days, and every device shows a warning. The quota, the headroom and the budgets keep such a
device from filling your disk with garbage. When an account exceeds a limit, the server logs an
"operator warning" and every device of the account shows a notice.

## Disk sizing

With quota Q, headroom H, account budget B per day, retention W days, minimum count cap C and
record cap R, one account can keep at most

```
3 × (Q + H) + B × (W + 1) + C + R
```

bytes stored, plus a few hundred bytes per version for the version history. With the defaults
(B = Q, W = 30, C = Q, R = 64 MiB) that is about `35 × Q`. Every byte a device makes
reachable again, also through a side commit of a merge, counts against the budget B, so no
device can keep old data stored beyond this bound by declaring it again before the window
ends. This is a worst case for an attacker on a
compromised device; ordinary use stays far below it, since old versions share most of their
data with the current one. On a disk that several accounts share, lower
`HANGAR_DRIVE_ACCOUNT_BUDGET` first.

## Admin commands

The commands run in the server container:

```sh
docker compose exec server hangar-drive-server <command>
```

| Command | What it does |
| --- | --- |
| `invite [--days N] [--pin [--cert FILE \| --spki SHA256-HEX]]` | Creates a single-use invite and prints its link ([Invite links](#invite-links)) |
| `status` | Accounts, devices, folders, live and stored bytes, pins, warnings, free disk space |
| `server-key-number [--cert FILE \| --spki SHA256-HEX]` | Prints the server key number (below) |
| `pin list` | Lists anomaly pins |
| `pin lift ACCOUNT COMMIT` | Lifts a pin, for example one set off by a garbage burst |
| `purge retained ACCOUNT [--yes]` | Deletes every version of an account that is not current, at once |
| `purge folder ACCOUNT FOLDER [--yes]` | Deletes one folder with all its versions |
| `purge account ACCOUNT [--yes]` | Deletes an account and everything it holds |
| `gc` | Runs one garbage collection step now |
| `healthcheck` | Used by the image's health check |

`gc` and the purges delete data and refuse to run while the server runs on the same data
folder (the server holds the lock file `server.lock` in it). Stop the server first and run
them in a one-off container:

```sh
docker compose stop server
docker compose run --rm server purge folder ACCOUNT FOLDER
docker compose start server
```

Purges cannot be undone. Without `--yes` they ask you to type the ID of what goes, the folder
ID for `purge folder` and the account ID otherwise, which needs a terminal (`docker compose
run` has one). After a purge, devices that were offline for longer than the retention window
ask their user to confirm the current state.

## Server key number

When devices pin a self-signed certificate, a new key on the server makes them stop syncing and
show "the server identifies itself differently than usual". They never accept a new key on
their own. To confirm the new key, compare the number the device shows with the one the server
prints:

```sh
docker compose exec server hangar-drive-server server-key-number --cert /path/in/container/cert.pem
# or with the SHA-256 of the certificate's public key:
openssl x509 -in cert.pem -pubkey -noout | openssl pkey -pubin -outform DER | openssl dgst -sha256
docker compose exec server hangar-drive-server server-key-number --spki <hex>
```

Both show six groups of five digits. Confirm on the device only if all of them match. When you
renew a self-signed certificate, keep its key, so devices need nothing. With a certificate from
a public authority (Let's Encrypt), devices use the system's trust store and renewals change
nothing.

## Backups (3-2-1)

The server is the backup of your devices against mistakes and compromised clients, but not
against a lost disk or a lost server. Keep three copies of the data on two different media,
one of them off site, for example the live volume, a nightly copy on another disk and a weekly
copy at another place. The data is encrypted, so the copies need no extra encryption to stay
confidential, but keep them away from the people who should not delete them.

A copy holds the whole data folder, not only the objects:

- `drive.sqlite3` (with `drive.sqlite3-wal` and `drive.sqlite3-shm` while the server runs): the
  metadata, that is accounts, device logs, commits, reference lists, pins, sealed records and
  the change feed. Without it the objects cannot be told apart or restored. It holds no file
  content and no names in the clear, but it does show which device wrote what and when, so
  treat it like the objects. Deleted rows are overwritten in the file (`secure_delete`), so an
  old copy holds only what was in the database when it was taken.
- `server.secret`: the 32 byte key of the sign-in challenges. Without it the server makes a new
  one, which only invalidates challenges in flight. It is still a secret: whoever holds it can
  forge challenges of this server (not proofs, which need a device's key), so keep the copies
  as protected as the volume and never in a public place.
- `objects/`: the encrypted objects.

A consistent copy needs the database and the objects from the same moment. The simplest way is
a short stop:

```sh
docker compose stop server
docker run --rm -v hangar-drive_drive-data:/data:ro -v "$PWD":/backup alpine \
  tar czf /backup/drive-$(date +%F).tar.gz -C /data .
docker compose start server
```

(The volume name is `<project folder>_drive-data`; `docker volume ls` shows it.) Devices that
are offline for those seconds catch up afterwards.

To restore, stop the server, replace the volume's contents with the copy and start it again.
Devices then see an older state than they knew. They do not take it silently: each one pauses
the affected folders and asks its user to confirm, ideally after comparing the folder safety
number with another device, and then publishes its local changes on top of the restored state.
Changes made after the backup survive on the devices that had them.

## Updates

```sh
git pull
docker compose up -d --build
```

Database migrations run at the start. Keep a backup from before the update. App and server
are released together; the health endpoint reports the protocol version.

## Logs

`docker compose logs server` shows one line per request with the route pattern, the status and
the time, never a path with IDs, a token or any content. Lines with `operator warning` need your
attention: a quota, a budget, a pin or the disk reserve.
