
## Disclamer

**⚠ WARNING:** **This is an EXPERIMENTAL Project, use it at your own risk!**
# Bepass: A DPI bypassing tool!

This is a simple tool that utilizes tls client hello splitting attack in order to bypass the iran's dpi system. It won't work if the target machine's ip is blocked(Yet ?!)



## Features

- Supports all Iran's network careers with some tweaks in tls hello packet length
- DOH support
- SDNS support
- Cross platform

## Build
You can build debug and release version as:

```bash
  git clone https://github.com/uoosef/bepass.git
  make # For debug version
  make release # For Release version
```

## Deployment
You can download the latest build from release or Just install go 1.19+ and run:

```bash
  git clone https://github.com/uoosef/bepass.git
  cd bepass/cmd/bepass
  go build .
```

It should give you an executable file, or you can simply run it in place.

```bash
  git clone https://github.com/uoosef/bepass.git
  cd bepass/cmd/bepass
  go run . -c config.json
```


## Usage

In order to deploy this project, you should first find a "DOH" or "SDNS" link that works on your ISP, then edit config.json and fill the "RemoteDNSAddr" field with the dns link that you found!
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
  "DelayBetweenChunks":   [1, 10]
}
```


## Roadmap

- Self-Hosted DOH (WIP)
  
- An android version (WIP)

- Finding a way to bypass the blocked ips


## License

[MIT](https://choosealicense.com/licenses/mit/) go nuts!

