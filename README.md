
# Bepass: DPI Bypassing Tool and Cloudflare Worker Proxy

![Disclaimer](https://img.shields.io/badge/⚠%20WARNING-EXPERIMENTAL-red)

## Table of Contents
- [Bepass: DPI Bypassing Tool and Cloudflare Worker Proxy](#bepass-dpi-bypassing-tool-and-cloudflare-worker-proxy)
  - [Table of Contents](#table-of-contents)
  - [Introduction](#introduction)
  - [Features](#features)
  - [Usage](#usage)
    - [Configuration Parameters](#configuration-parameters)
  - [Build Instructions](#build-instructions)
    - [CLI Version](#cli-version)
    - [GUI Version (Work in Progress)](#gui-version-work-in-progress)
  - [Deployment](#deployment)
    - [CLI Deployment](#cli-deployment)
  - [Roadmap](#roadmap)
  - [License](#license)

## Introduction

Bepass is an advanced tool designed to bypass Iran's Deep Packet Inspection (DPI) system using a TLS client hello splitting attack. It also enables the deployment of a VLESS-like proxy on Cloudflare Workers. This README provides an overview of the project's features, build instructions, deployment guidelines, and more.

## Features

- **DPI Bypass:** Supports all of Iran's network carriers with customized TLS hello packet length adjustments.
- **DNS Over HTTPS (DOH) Support:** Facilitates secure and private DNS resolution.
- **Server Name Indication DNS (SDNS) Support:** Enhances DNS resolution efficiency.
- **Cross-Platform Compatibility:** Suitable for various operating systems.
  
## Usage

You can run the CLI version of Bepass as follows:
1. download the latest release from [here](https://github.com/uoosef/bepass/releases) based on your operating system
2. extract the zip file
3. create a `config.json` file in the same directory as the executable file
4. run the executable file

Example Configuration(`config.json` file) for IR-MCI:

```json
{
  "TLSHeaderLength": 5,
  "TLSPaddingEnabled": false,
  "TLSPaddingSize": [
    40,
    80
  ],
  "RemoteDNSAddr": "https://1.1.1.1/dns-query",
  "EnableDNSFragmentation": false,
  "DnsCacheTTL": 3000000,
  "DnsRequestTimeout": 10,
  "BindAddress": "0.0.0.0:8085",
  "ChunksLengthBeforeSni": [
    2000,
    2000
  ],
  "SniChunksLength": [
    1,
    2
  ],
  "ChunksLengthAfterSni": [
    2000,
    2000
  ],
  "DelayBetweenChunks": [
    10,
    20
  ],
  "WorkerAddress": "https://<your_worker>.workers.dev/dns-query",
  "WorkerIPPortAddress": "104.16.246.91:8443",
  "WorkerEnabled": true,
  "WorkerDNSOnly": false,
  "EnableLowLevelSockets": false,
  "Hosts": [
    {
      "Domain": "yarp.lefolgoc.net",
      "IP": "5.39.88.20"
    }
  ],
  "UDPBindAddress": "0.0.0.0",
  "UDPReadTimeout": 120,
  "UDPWriteTimeout": 120,
  "UDPLinkIdleTimeout": 120
}
```
### Configuration Parameters

1. `"TLSHeaderLength": 5`: Specifies the length of the TLS header, which is set to 5 bytes.

2. `"TLSPaddingEnabled": false`: Disables/Enable TLS padding.

3. `"TLSPaddingSize": [40, 80]`: Sets the TLS padding size range to be between 40 and 80 bytes.

4. `"RemoteDNSAddr": "https://1.1.1.1/dns-query"`: Specifies the remote DNS address for DNS queries. In this case, it's set to Cloudflare's DNS over HTTPS (DOH) service.

5. `"EnableDNSFragmentation": false`: Disables/Enable DNS fragmentation.

6. `"DnsCacheTTL": 3000000`: Sets the Time To Live (TTL) for DNS cache entries(seconds).

7. `"DnsRequestTimeout": 10`: Sets the timeout for DNS requests to 10 seconds.

8. `"BindAddress": "0.0.0.0:8085"`: Sets the bind address for the proxy server to listen on all available network interfaces (`0.0.0.0`) on port `8085`.

9. `"ChunksLengthBeforeSni": [2000, 2000]`: Specifies the length of chunks before the Server Name Indication (SNI) in the TLS handshake to be 2000 bytes.

10. `"SniChunksLength": [5, 10]`: Sets the SNI chunk length to be between 5 and 10 bytes.

11. `"ChunksLengthAfterSni": [2000, 2000]`: Specifies the length of chunks after the SNI in the TLS handshake to be 2000 bytes.

12. `"DelayBetweenChunks": [10, 20]`: Sets the delay between sending chunks to be between 10 and 20 milliseconds.

13. `"WorkerAddress": "https://<your_worker>.workers.dev/dns-query"`: Specifies the Cloudflare Worker address for proxy services.

14. `"WorkerIPPortAddress": "104.17.196.93:2096"`: Sets the IP address and port for the Cloudflare Worker.find clean CF IP and repalce it with this one to get better performance based on your internet quality and isp.

15. `"WorkerEnabled": true`: Disables/Enable the use of the Cloudflare Worker.

16. `"WorkerDNSOnly": false`: Indicates whether the Cloudflare Worker should be used for DNS queries only(If you just want to use the DOH over the worker set `true`. But if you want a full-fledged TCP SOCKS5 proxy over the worker set `false`).

17. `"EnableLowLevelSockets": false`: Disables/Enable low-level socket functionality.

18. `"Hosts": [{ "Domain": "yarp.lefolgoc.net", "IP": "5.39.88.20" }]`: Specifies a list of custom hosts to map domain names to IP addresses. In this example, "yarp.lefolgoc.net" is mapped to "5.39.88.20."

19. `"UDPBindAddress": "0.0.0.0"`: Sets the UDP bind address to listen on all available network interfaces (`0.0.0.0`).

20. `"UDPReadTimeout": 120`: Sets the UDP read timeout to 120 seconds.

21. `"UDPWriteTimeout": 120`: Sets the UDP write timeout to 120 seconds.

22. `"UDPLinkIdleTimeout": 120`: Sets the UDP link idle timeout to 120 seconds.

Please note that you should replace `<your_worker>` in `"WorkerAddress"` with your actual Cloudflare Worker address. Additionally, ensure that you configure other settings as needed for your specific use case.

## Build Instructions

### CLI Version

You can build the CLI version of Bepass as follows:

```bash
git clone https://github.com/uoosef/bepass.git
cd bepass/bepass
make           # Build CLI debug version
make release   # Build CLI release version
```

### GUI Version (Work in Progress)
You can build GUI debug and release versions as follows:

```bash
  git clone https://github.com/uoosef/bepass.git
  cd bepass/bepass
  make gui # For GUI debug version
  make gui-release # For GUI release version
```

A graphical user interface (GUI) version of Bepass is under development. Stay tuned for updates on its availability.

## Deployment

### CLI Deployment

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

## Roadmap

project roadmap includes:

- [x] Self-Hosted DOH (Completed)
- [x] TCP Proxy Over Worker (Completed)
- [ ] GUI Version (Work in Progress)
- [ ] Android Version (Work in Progress)
- [ ] Finding a Way to Bypass Blocked IPs

## License

This project is open-source and licensed under the [MIT License](https://choosealicense.com/licenses/mit/). Feel free to contribute and use it in accordance with the license terms.

⚠ Use this tool responsibly and ensure compliance with local laws and regulations. ⚠