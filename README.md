## Disclaimer

**⚠ WARNING:** **This is an EXPERIMENTAL Project, use it at your own risk!**
# Bepass: A DPI bypassing tool and Socks over Cloudflare Worker Proxy!

This is a simple tool that utilizes tls client hello splitting attack in order to bypass Iran's DPI system. It won't work if the target machine's IP is blocked(Yet ?!)
\
\
It also allows you to deploy a free and fast VLESS-like proxy on Cloudflare Workers. Just copy the worker.js to your worker and fill configs accordingly; it will do the rest.



## Features

- Supports all of Iran's network carriers with some tweaks in TLS hello packet length.
- DOH support
- SDNS support
- Cross-platform

## Build (CLI)
You can build CLI debug and release versions as follows:

```bash
  git clone https://github.com/uoosef/bepass.git
  cd bepass/bepass
  make # For CLI debug version
  make release # For CLI Release version
```

## Build (GUI) (WIP)
You can build GUI debug and release versions as follows:

```bash
  git clone https://github.com/uoosef/bepass.git
  cd bepass/bepass
  make gui # For GUI debug version
  make gui-release # For GUI release version
```

## Deployment (CLI)
You can download the latest build from the release or just install Go 1.19+ and run:

```bash
  git clone https://github.com/uoosef/bepass.git
  cd bepass/bepass
  go build ./cmd/cli/main.go
```

It should give you an executable file, or you can simply run it in place.

```bash
  git clone https://github.com/uoosef/bepass.git
  cd bepass/bepass
  go run ./cmd/cli/main.go -c config.json
```


## Usage

In order to deploy this project, you should first find a "DOH" or "SDNS" link that works on your ISP, then edit config.json and fill the "RemoteDNSAddr" field with the DNS link that you found!
\
\
For example, the following configuration will most likely work on IR-MCI:


```json
  {
  "TLSHeaderLength": 5,
  "RemoteDNSAddr": "https://1.1.1.1/dns-query",
  "DnsCacheTTL": 30,
  "BindAddress": "127.0.0.1:8085",
  "ChunksLengthBeforeSni": [1, 5],
  "SniChunksLength": [1, 5],
  "ChunksLengthAfterSni": [1, 5],
  "DelayBetweenChunks":   [1, 10],
  "WorkerAddress": "https://<YOUR_WORKER_ADDRESS>/dns-query",
  "WorkerIPPortAddress": "<CLEAN_CLOUDFLARE_IP>:443",
  "WorkerEnabled": true,
  "WorkerDNSOnly": true
}
```
If you can't find any working DOH Servers, you can deploy worker.js code to your CF worker and change config.json accordingly
\
\
If you just want to use the DOH over the worker set WorkerDNSOnly to true
```json
{
  "WorkerDNSOnly": true
}
```
But if you want a full-fledged TCP SOCKS5 proxy over the worker set WorkerDNSOnly to false. Please consider that your UDP traffic wouldn't go through the worker because CF doesn't support UDP outgoing sockets currently
```json
{
  "WorkerDNSOnly": false
}
```

## Roadmap

- Self-Hosted DOH (DONE)
- TCP PROXY Over Worker (DONE)
- A GUI Version (WIP)
- An Android version (WIP)
- Finding a way to bypass the blocked IPs


## License

[MIT](https://choosealicense.com/licenses/mit/) go nuts!