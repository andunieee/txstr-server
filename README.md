# txstr-server

Optional self-hosted companion to [txstr](https://github.com/andunieee/txstr).

This is not required for using `txstr`. Only use it if you like to self-host your own stuff or from friends and don't want to depend on third-party hosted servers.

The server is very simple and efficient, it should have very low CPU/RAM use and run fine on the cheapest VPS even if you have many friends using it.

## Install

Download a binary from [releases](https://github.com/andunieee/txstr-server/releases), or build with Cargo:

```sh
cargo install --git https://github.com/andunieee/txstr-server
```

## Run

Declare your pubkey as admin (hex or `npub`, repeatable for multiple admins):

```sh
txstr-server --admin <your-pubkey> --listen 127.0.0.1:22223 --data ./data
```

Full options (`txstr-server --help`):

```text
--listen <ADDR>  address to listen on [default: 0.0.0.0:22223]
--data <DIR>     directory where events and settings are stored [default: ./data]
--admin <KEY>    pubkey allowed to manage the server, can be repeated (required)
--no-images      reject notes/comments that link to images
```

## Storage

All state lives under `--data` (default `./data`):

- `settings.json` — local config file (server name, description, whitelist, bans, blocked kinds/IPs)
- `events/` — LMDB database with stored events

Back up that directory and you back up the server. Delete a ban entry from `settings.json` style state only via management API; restarts persist everything.

## Deploy

Put a reverse proxy in front, as standard procedure. Gives it a domain name and TLS. Proxy both HTTP and WebSocket to the server — it serves both on the same port.

Caddy example:

```text
example.com {
    reverse_proxy 127.0.0.1:22223
}
```

Then run the server bound to localhost (`--listen 127.0.0.1:22223`) and point `txstr` at `wss://example.com`.

## Configure

Most configuration is done from `txstr` itself: add your server URL there and declare it as owned by you (your `--admin` pubkey). After that, whitelist, bans, kinds, name/description/icon can be managed directly from `txstr`. No need to SSH in and edit files.
