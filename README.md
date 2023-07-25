
## Disclamer

**⚠ WARNING:** **This is a SHITTY Code use it at your own risk!**
# Bepass: A DPI bypassing tool!

This is a simple tool that utilizes tls client hello splitting attack inorder to bypass iran's dpi system, it won't work if target machine's ip is blocked(Yet ?!)



## Features

- Supports all irans network careers with some tweaks in tls hello packet length
- DOH spport
- SDNS support
- Cross platform


## Usage

Inorder to deploy this project you should first find a "DOH" or "SDNS" link that works on your career, then edit config.json and fill the "RemoteDNSAddr" field respectivce to the dns link that you found!
\
\
For Example the following configuration will most likely work on IR-MCI:


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



## Deployment
Just install go 1.19+ and run:

```bash
  go build .
```

It should gives you an executable file. or you can simple run it in place

```bash
  go run . -c config.json
```
## Roadmap

- An android version

- Finding a way to bypass the blocked ip's


## License

[MIT](https://choosealicense.com/licenses/mit/) go nuts!

