# Self-hosting the Hangar Drive server

The Hangar Drive server keeps your devices in sync and keeps every version for a retention
window that you, the operator, choose. Everything it stores is end-to-end encrypted: it sees
object sizes (padded), counts and times, but no file names, paths or contents.

This guide covers installation, the first invite, a reverse proxy with TLS, configuration,
backups, updates and the server key number.

## Requirements

- A Linux host (x86-64 or ARM64) with Docker and Docker Compose 2.24 or newer, or a NAS with a
  container app ([On a NAS](#on-a-nas-bind-mount-and-your-own-user)).
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

3. Put a reverse proxy with TLS in front of it ([Caddy](#caddy), [nginx](#nginx) or
   [Nginx Proxy Manager](#nginx-proxy-manager)).

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

   No terminal on the host (a NAS whose container app only shows logs)? While no account exists,
   the server prints an invite link in its log at every start, after `server ready`:
   `no account yet: open this invite link ... link=https://drive.example.org/join#...`. Each
   start replaces the previous one, so take the link from the newest start. Once the first
   account exists (the log says `account created`), no further link is printed; invites for
   other people come from the `invite` command. Until then, anyone who can read the server's
   log can create the account with that link, so keep the log as private as the host. The link
   needs the default log level (`RUST_LOG` at `info`) and carries no pin: with a self-signed
   certificate, create the invite with `invite --pin` instead.

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
		Strict-Transport-Security "max-age=31536000"
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
    add_header Strict-Transport-Security "max-age=31536000" always;

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

    location /api/v1/folders/ {
        proxy_pass http://127.0.0.1:8080;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_request_buffering off;
        # A large commit is checked set by set before it answers, and a download of a large
        # object waits on the disk: more than nginx's default of 60 s.
        proxy_read_timeout 300s;
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

### Nginx Proxy Manager

Nginx Proxy Manager (NPM) runs in a container of its own. It can reach the server in two ways;
choose one and trust exactly the address the server sees for it.

**A. A shared network (recommended when you can edit NPM's compose file).** The port stays
unpublished or bound to `127.0.0.1`, and NPM talks to the server directly. Attach the NPM
container to the server's Compose network with a fixed address. The network is named after the
folder of `docker-compose.yml`, usually `hangar-drive_drive`; `docker network ls` shows it. In
NPM's own compose file:

```yaml
services:
  npm:
    # ... your existing NPM service ...
    networks:
      default:
      drive:
        # One fixed address on the server's network: the only one the server trusts.
        ipv4_address: 172.30.250.20

networks:
  drive:
    external: true
    name: hangar-drive_drive
```

Then set `HANGAR_DRIVE_TRUSTED_PROXIES: 172.30.250.20` in the `server` service and run
`docker compose up -d` there. Forward host in NPM: `server`, port `8080`.

**B. The published port (a NAS whose container app cannot change NPM's network).** Publish the
port on the host (`ports: ["8095:8095"]` with `HANGAR_DRIVE_PORT: "8095"`) and let NPM forward to
the host's LAN address on that port. Docker passes such a connection from NPM's network into the
server's network and rewrites its source to the gateway of the server's network, so the server
sees every request from NPM (and from any other container or process on the host) as coming from
that gateway, while devices in the LAN that open the port directly keep their own addresses.
Give the server's network a fixed range, so its gateway stays the same when the project is
deployed again, and trust that gateway:

```yaml
services:
  server:
    environment:
      HANGAR_DRIVE_TRUSTED_PROXIES: 172.22.0.1
networks:
  default:
    ipam:
      config:
        - subnet: 172.22.0.0/16
          gateway: 172.22.0.1
```

The same holds when NPM runs with host networking. Be clear about what this trusts: **every
process of the host and every container on it** arrives from that gateway and may then set
`X-Forwarded-For`, that is, choose its own rate limit key; a trusted address also gets a
connection limit of its own, half of the server's 4096 slots, instead of the per client limit.
Run nothing on the host you would not trust with that.

Bind the published port to one IPv4 address instead of every interface, for example
`"0.0.0.0:8095:8095"` rather than `"8095:8095"`. The short form also listens on IPv6 (`[::]`),
and depending on Docker's configuration such connections pass through `docker-proxy` and may
reach the server from the gateway address as well, trusted like NPM. Stricter still is
`"172.22.0.1:8095:8095"`, the gateway itself, with `172.22.0.1` as NPM's forward host: the
port is then no longer open in the LAN at all.

Check it once from another machine in the LAN, over IPv4 and over IPv6 if the host has an IPv6
address:

```sh
curl -4 -H 'X-Forwarded-For: 203.0.113.9' http://<host LAN address>:8095/api/v1/health
curl -6 -H 'X-Forwarded-For: 203.0.113.9' 'http://[<host IPv6 address>]:8095/api/v1/health'
```

Each answered request from a device of the LAN must leave an `operator warning: a local address
sends X-Forwarded-For` in the server's log (once per address); if it does not, that connection
arrived as the gateway and can forge its client address, so bind the port more narrowly. A
refused connection is fine.

The port is reachable as plain HTTP wherever it is bound. Never use it from a device: only the
sign-in proof is signed and bound to the public URL; every call after it carries a bearer token,
which plain HTTP would expose to anyone on the way. The app therefore allows `http` only for
`localhost`.

Not sure which address NPM arrives from? Leave the setting empty, make one request through NPM
and look for the `operator warning` in the server's log: it names the local address that sent
`X-Forwarded-For` without being trusted. Trust that exact address, never a range.

The proxy host in NPM:

- **Details:** domain `drive.example.org`, scheme `http`, forward host as above (`server`, or
  the host's LAN address for B), port `8080` (or the published port). Turn on *Websockets
  Support*; leave *Cache Assets* off.
- **SSL:** a Let's Encrypt certificate, *Force SSL*, *HTTP/2 Support* and *HSTS Enabled*;
  leave *HSTS Subdomains* off unless every host under your domain is served over HTTPS, since
  it binds all of them. Behind a proxy the server sends no HSTS of its own (only when it
  terminates TLS itself), so NPM's setting is the one that counts.
- **Advanced:** the following custom configuration. NPM puts it into the proxy host's `server`
  block next to its own `location /`, which inherits every line, so it needs no `location` and
  no forward address of its own.

```nginx
# The largest request is a commit of 80 MiB (objects are at most about 34 MiB): above the
# server's limits, so the server and not the proxy refuses and names the reason.
client_max_body_size 100m;
# Slow clients: headers within 10 s, no pause longer than 30 s in a body.
client_header_timeout 10s;
client_body_timeout 30s;
# Uploads go to the server as they arrive. With buffering, NPM first writes every upload to
# its own disk and only then sends it on: twice the disk writes and a stalled sync.
proxy_request_buffering off;
# Replies stay buffered in memory but are never spooled to a temporary file on the proxy's
# disk (every 4 MiB chunk would be). Buffering in memory keeps downloads fast; the event
# stream is never buffered, since the server sends `X-Accel-Buffering: no` with it.
proxy_max_temp_file_size 0;
# NPM's default timeouts are 90 s; a large commit is checked before it answers, a download
# waits on the disk, and the event stream sends a keepalive every 25 s.
proxy_read_timeout 300s;
proxy_send_timeout 300s;
proxy_connect_timeout 10s;
# Encrypted objects do not compress, and the server compresses nothing either.
gzip off;
# No access log: it would keep every client address with the request paths.
access_log off;
```

Do not add `proxy_http_version` here: it is NPM's default already, and with *Websockets
Support* NPM sets it in the same `server` block, so nginx would refuse the duplicate and NPM
would take the host offline. NPM's generated `location /` sets `Host` and appends the client
address to `X-Forwarded-For` itself; the generated files in `/data/nginx/proxy_host/` inside the
NPM container show what your version does. NPM has no setting for connections per client
address; as with Caddy, put a firewall rule in front of port 443 if you expect abuse.

**Slow uploads?** Every request leaves one log line with the route and the time the server
spent on it in milliseconds, for example
`docker compose logs server | grep 'PUT' | grep 'objects/{id}'`. If these `ms` values stay
small while a device uploads slowly, the time goes elsewhere: request buffering in the proxy,
the network, or the device. If they are large, the server waits on its disk: every stored
object is flushed to disk before it is confirmed (the file, its directory and the database
entry), so each small upload costs three disk flushes. An SSD does that in a few
milliseconds; a spinning disk needs about 10 to 20 ms per flush, so there a single upload takes
30 ms or more, and uploads in parallel help only partly. Writes to the database take turns in
the order they arrive, so no upload waits longer than the ones before it.

### On a NAS (bind mount and your own user)

NAS container apps (UGOS, DSM, QNAP and others) usually take a Compose file pasted into the web
interface and keep the data in a shared folder, not in a Docker volume. Three things differ from
the default `docker-compose.yml`:

- **Data folder:** mount the folder instead of the volume, for example
  `- /volume1/drive:/data`. Create the folder in the NAS's file manager first.
- **User:** the image runs as user `65532` by default. A folder made in the file manager belongs
  to a NAS user instead, so run the container as that user with `user: "<uid>:<gid>"` (for
  example `user: "1000:100"`), or give the folder to `65532`. If the two do not match, the server
  stops at once and its log says whose the folder is and which user it runs as. Do not combine
  `user:` with a named volume: Docker gives a new volume to the image's user, and the server
  could not write to it.
- **No terminal:** the first invite link appears in the container log
  ([Install](#install-in-five-steps), step 4), and so does what the server runs with: right after
  `server ready` (public URL, trusted proxies, limits) a line `data` with the number of accounts
  and the free disk space.

Everything else stays as in `docker-compose.yml`: `read_only: true`, `cap_drop: [ALL]`,
`no-new-privileges`, the memory and process limits, the log rotation and
`stop_grace_period`. For a reverse proxy on the same NAS see
[Nginx Proxy Manager](#nginx-proxy-manager), variant B.

### TLS in the server instead of a proxy

The server can terminate TLS 1.3 itself. Mount the certificate chain and key (PEM) into the
container and set `HANGAR_DRIVE_TLS_CERT` and `HANGAR_DRIVE_TLS_KEY`. Then bind the port to the
network instead of `127.0.0.1`. A reverse proxy remains the recommended setup: it renews
certificates on its own. A server that terminates TLS itself sends
`Strict-Transport-Security: max-age=31536000` on every reply (without `includeSubDomains`,
which would bind other hosts of the domain); behind a proxy it sends none, so set it in the
proxy as shown above.

- **No trusted proxies:** with TLS in the server, `HANGAR_DRIVE_TRUSTED_PROXIES` must be empty,
  and the server refuses to start otherwise. Nothing sits in front of it then, so a client
  that can reach the port directly could send its own `X-Forwarded-For` from an address that
  was once your proxy's and choose its rate limit key. Remove the line when you move from a
  proxy to this setup.
- **Certificate renewal:** the server reads the certificate and key at start only. After
  replacing the files, restart it (`docker compose restart server`).
- **Connections:** without a proxy the server's own limits apply to every client: at most
  `HANGAR_DRIVE_CONNECTIONS_PER_IP` connections per address (IPv6: per /64), and while fewer
  than half of the server's 4096 connection slots are free, four times as many per network
  (IPv4 /24, IPv6 /48, at most 1024); a TLS handshake must finish within 5 seconds.

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
| `HANGAR_DRIVE_BIND` | `0.0.0.0` in the image, `127.0.0.1` otherwise | Address to listen on (IPv4 or IPv6, for example `::`); in the image the port mapping decides who reaches it |
| `HANGAR_DRIVE_PUBLIC_URL` | none, required | The address devices reach the server under, for the links `invite` prints and the sign-in check ([Invite links](#invite-links)); the server does not start without it |
| `HANGAR_DRIVE_DATA_DIR` | `/data` in the image | Database and objects |
| `HANGAR_DRIVE_RETENTION_DAYS` | `30` | How long a version stays restorable after it was replaced (W) |
| `HANGAR_DRIVE_RETENTION_MIN_COMMITS` | `10` | Newest versions per folder kept regardless of age, within the minimum count cap |
| `HANGAR_DRIVE_QUOTA` | `100GiB` | Live bytes per account (Q); old versions do not count |
| `HANGAR_DRIVE_HEADROOM` | 1% of Q, at least 64 MiB | Extra room for directory listings, so deleting works at a full quota (H) |
| `HANGAR_DRIVE_MIN_COUNT_CAP` | Q | Bytes that only the minimum count keeps, per account (C) |
| `HANGAR_DRIVE_ACCOUNT_BUDGET` | Q | Bytes an account may make live per 24 hours (B) |
| `HANGAR_DRIVE_DEVICE_BUDGET` | half the account budget | Bytes one device may make live per 24 hours; at most the account budget |
| `HANGAR_DRIVE_DISK_RESERVE` | `1GiB` | Below this much free disk space, uploads are refused |
| `HANGAR_DRIVE_TRUSTED_PROXIES` | empty | Comma-separated addresses of reverse proxies (CIDR ranges are accepted; prefer the exact address); must be empty with TLS in the server |
| `HANGAR_DRIVE_RECORD_CAP` | `64MiB` | Bytes of encrypted account records (folder keys, folder list, device names) per account (R) |
| `HANGAR_DRIVE_HEAVY_REQUESTS` | `4` | Commits and record writes worked on at once, from `1` to `4`; their bodies are held in memory, and a waiting commit holds one of the server's 8 database connections, so at most half of them go to commits |
| `HANGAR_DRIVE_UPLOADS_PER_ACCOUNT` | `8` | Uploads one account may have in flight at once |
| `HANGAR_DRIVE_UPLOADS_PER_MINUTE` | `1200` | Uploads one account may start per minute, over all its devices, from `60` to `12000`. Every file is at least two uploads, so the default allows about 10 small files a second; raise it if a first sync of many small files is too slow and the disk keeps up. A device's limit for all its calls grows with it. High values only make sense with few accounts you trust: every upload goes through the one database write path, so one account at a high rate can slow the uploads of all others |
| `HANGAR_DRIVE_CONNECTIONS_PER_IP` | `64` | Open connections per client address; while the server's connection slots run short, a client network (IPv4 /24, IPv6 /48) gets four times as many, at most 1024; a trusted proxy may hold 2048 (half of the server's 4096 slots) and has no network cap |
| `HANGAR_DRIVE_TLS_CERT`, `HANGAR_DRIVE_TLS_KEY` | empty | PEM files for TLS in the server |
| `HANGAR_DRIVE_GC_INTERVAL_MINUTES` | `60` | Minutes between two garbage collection steps |
| `HANGAR_DRIVE_SHUTDOWN_GRACE_SECS` | `10` | How long a shutdown waits for open requests |
| `HANGAR_DRIVE_ANOMALY_MIN_OBJECTS` | `500` | Replaced or dropped file objects within an hour that always count as a burst; a smaller folder needs `HANGAR_DRIVE_ANOMALY_PERCENT` of its file objects, at least 20 |
| `HANGAR_DRIVE_ANOMALY_PERCENT` | `30` | Share of a folder's data (and of its file objects) a burst must replace or drop; retiring a folder counts as dropping all of it |
| `TOKIO_WORKER_THREADS` | one per CPU the container may use | Threads that serve requests; the default follows a CPU limit (`cpus:` in Compose). File work runs on at most 64 further threads, well within the process limit of `docker-compose.yml` |
| `RUST_LOG` | `info` | Log level |
| `SQLITE_TMPDIR` | `/data/tmp` in the image | Where SQLite writes large temporary tables and sorts; the image's root file system is read-only, so it points into the data volume. The server creates `tmp` in the data folder and empties it at every start |

At every start the server makes its data folder and the `tmp` folder in it private to its own
user (mode `0700`). Outside the image this keeps the database and `server.secret` unreadable
for other users of the host whatever the umask was.

### What the limits protect against

A device that is compromised (for example by ransomware) can rewrite or delete your files. It
cannot delete old versions: no client call deletes anything, and old versions stay for the
retention window. A burst of replaced or dropped files pins the last version before it for 90
days, and every device shows a warning. The quota, the headroom and the budgets keep such a
device from filling your disk with garbage. When an account exceeds a limit, the server logs an
"operator warning" and every device of the account shows a notice.

Such a device also cannot lock the other devices of the account out. Uploads that no commit
has named yet count against the quota only for the device that sent them, and removing a device
deletes them at once and gives back the budget they used. The device budget defaults to half the
account budget, so one device never uses up the budget of the others. One device then uploads at
most half a quota per day; if a first upload of a full quota from a single device should fit in
one day, raise `HANGAR_DRIVE_ACCOUNT_BUDGET` (which raises the disk bound below) or set
`HANGAR_DRIVE_DEVICE_BUDGET` to the account budget (which gives up this protection).

Such a device can also not fill the device log, the list of the account's devices, until it can
no longer be removed: adding devices is limited to 30 per hour and account, and removing a
device is never limited. Calls with a valid session count per device, never against the
limits of its address, so a device in the same household (same public address) cannot lock the
others out, also not with made-up session tokens, and cannot keep them from removing it.
Commits are limited to 30 per minute and device and 120 per account; a device whose commits are
refused 20 times within 10 minutes (other than because another device committed first) waits
for the rest of those 10 minutes, and so does the whole account after 60, so no device can keep
the database busy for the others with commits that never pass. While another commit or record
write waits for one of the `HANGAR_DRIVE_HEAVY_REQUESTS` slots, a large body that arrives slower
than 64 KiB/s on average is cut off and its device tries again; without such a wait a slow
connection only has to finish within two minutes.

A refused call answers `429` with `Retry-After` set to the seconds until the limit that refused
it has room again, so devices wait exactly as long as needed.

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
docker run --rm --entrypoint sh \
  -v hangar-drive_drive-data:/data:ro -v "$PWD":/backup \
  caddy:2.10.2-alpine@sha256:4c6e91c6ed0e2fa03efd5b44747b625fec79bc9cd06ac5235a779726618e530d \
  -c "umask 077 && tar czf /backup/drive-$(date +%F).tar.gz -C /data . \
      && chown $(id -u):$(id -g) /backup/drive-$(date +%F).tar.gz"
docker compose start server
```

(The volume name is `<project folder>_drive-data`; `docker volume ls` shows it.) Devices that
are offline for those seconds catch up afterwards.

The archive holds `server.secret`, so it is a secret itself: the command writes it with mode
`0600` (`umask 077`) and gives it to your user. Store and move it only where the volume itself
may go. The command runs `tar` from the Caddy image that `docker-compose.yml` already pins by
digest; any image with a shell and `tar` works, ideally pinned by digest the same way.

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

To build the image for another machine, for example an ARM64 NAS, from an x86-64 one (both
platforms are cross-compiled, nothing runs under emulation):

```sh
docker buildx build -f server/Dockerfile --platform linux/amd64,linux/arm64 \
  --build-arg VERSION=<version> --build-arg REVISION=$(git rev-parse HEAD) \
  --build-arg SOURCE_DATE_EPOCH=$(git log -1 --format=%ct) \
  -t <registry>/hangar-drive-server:<version> --push .
```

`VERSION` and `REVISION` go into the image's labels; `SOURCE_DATE_EPOCH` makes BuildKit date
the image by the last commit instead of the build time, so the same commit gives the same image
metadata.

Database migrations run at the start. Keep a backup from before the update. App and server
are released together; the health endpoint reports the protocol version.

## Logs

`docker compose logs server` shows one line per request with the route pattern, the status and
the time in milliseconds (`ms`), never a path with IDs, a token or any content. Lines with
`operator warning` need your attention: a quota, a budget, a pin, the disk reserve or an
untrusted proxy. The logging settings in `docker-compose.yml` keep at most five log files of
10 MB each.

An hour after every start, and then once a day, the server removes object files that no
database entry names (left by a crash between storing a file and recording it).
