# workers-tunnel

[![Deploy to Cloudflare Workers](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/zhu327/workers-tunnel/tree/main)

Edge network tunnel implemented using Cloudflare Workers.

It is recommended to use Xray as the tunnel client.

<https://github.com/XTLS/Xray-core>

Use the following rules to split traffic by file and route Cloudflare IP directly.

<https://github.com/Loyalsoldier/v2ray-rules-dat>

Due to the limitations of Cloudflare Workers, UDP proxy is not supported, and it is not possible to use proxy to connect to Cloudflare's IP addresses. It is recommended to use the following routing configuration to establish a direct connection to Cloudflare's IP addresses.

Replace the domain `your.domain.workers.dev` in the following configuration with your Cloudflare Workers domain.

```json
{
  "log": {
    "loglevel": "warning"
  },
  "inbounds": [
    {
      "port": 1080,
      "protocol": "socks",
      "sniffing": {
        "enabled": true,
        "destOverride": [
          "http",
          "tls"
        ]
      },
      "settings": {
        "auth": "noauth"
      }
    }
  ],
  "outbounds": [
    {
      "settings": {
        "vnext": [
          {
            "port": 443,
            "users": [
              {
                "id": "c55ba35f-12f6-436e-a451-4ce982c4ec1c",
                "encryption": "none"
              }
            ],
            "address": "your.domain.workers.dev"
          }
        ]
      },
      "protocol": "vless",
      "streamSettings": {
        "network": "ws",
        "tlsSettings": {
          "serverName": "your.domain.workers.dev",
          "fingerprint": "chrome"
        },
        "wsSettings": {
          "headers": {
            "Host": "your.domain.workers.dev"
          },
          "path": "/ws?ed=512"
        },
        "security": "tls"
      }
    },
    {
      "protocol": "freedom",
      "settings": {},
      "tag": "direct"
    }
  ],
  "routing": {
    "domainStrategy": "IPIfNonMatch",
    "rules": [
      {
        "type": "field",
        "outboundTag": "direct",
        "domain": [
          "geosite:cn"
        ]
      },
      {
        "type": "field",
        "outboundTag": "direct",
        "ip": [
          "geoip:cn",
          "geoip:private",
          "geoip:cloudflare"
        ]
      }
    ]
  }
}
```

Please refer to the following documentation for development and deployment.

<https://developers.cloudflare.com/workers/runtime-apis/webassembly/rust/>

## Configuration

`USER_ID` is the only credential the tunnel has, so set it as a secret rather
than as a var. Values under `[vars]` are committed to the repository and are
readable from the Cloudflare dashboard; a UUID published next to the code makes
the worker an open proxy for anyone who reads it.

```sh
wrangler secret put USER_ID
```

Until it is set, the worker refuses tunnel traffic. The same applies to the
one-click deploy button: deploy first, then set the secret.

The remaining settings stay in `[vars]` and are all optional:

| Variable | Default | Purpose |
| --- | --- | --- |
| `FALLBACK_SITE` | unset | Site to mirror for requests that are not tunnel upgrades. Without it they answer `404`. Worth setting: a worker that responds distinctively to ordinary HTTP is easy to pick out of a scan of `workers.dev`. |
| `PROXY_IP` | unset | Whitespace-separated relays tried in order when the destination refuses the connection. An entry may pin its own port (`proxy.example:8443`); one without a port uses the port the client asked for. |
| `SHOW_URI` | `false` | Serves the `vless://` URI at `/<USER_ID>`. It hands the full credential to anyone who can reach that path, so leave it off unless you are actively provisioning a client. |

## Setup

To create a `my-project` directory using this template, run:

```sh
$ npm init cloudflare my-project workers-tunnel
# or
$ yarn create cloudflare my-project workers-tunnel
# or
$ pnpm create cloudflare my-project workers-tunnel
```

> **Note:** Each command invokes [`create-cloudflare`](https://www.npmjs.com/package/create-cloudflare) for project creation.

## Usage

This template starts you off with a `src/lib.rs` file, acting as an entrypoint for requests hitting your Worker. Feel free to add more code in this file, or create Rust modules anywhere else for this project to use.

With `wrangler`, you can build, test, and deploy your Worker with the following commands:

```sh
# run your Worker in an ideal development workflow (with a local server, file watcher & more)
$ npm run dev

# deploy your Worker globally to the Cloudflare network (update your wrangler.toml file for configuration)
$ npm run deploy
```

Read the latest `worker` crate documentation here: https://docs.rs/worker

## WebAssembly

`workers-rs` (the Rust SDK for Cloudflare Workers used in this template) is meant to be executed as compiled WebAssembly, and as such so **must** all the code you write and depend upon. All crates and modules used in Rust-based Workers projects have to compile to the `wasm32-unknown-unknown` triple.

Read more about this on the [`workers-rs`](https://github.com/cloudflare/workers-rs) project README.

## Issues

If you have any problems with the `worker` crate, please open an issue on the upstream project issue tracker on the [`workers-rs` repository](https://github.com/cloudflare/workers-rs).
