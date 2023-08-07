## Build
You can build tun2socks.go to tun2socks.aar android library with following commands
\
\
This requires 'javac' (version 1.7+) and Android SDK (API level 16 or newer) to build the library for Android

```bash
  go install golang.org/x/mobile/cmd/gomobile@latest
  gomobile init
  gomobile bind -target=android .
```
