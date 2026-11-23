# flux

Live DNS traffic observer for the CDT bundle (v0.1.0, phase 1 foundation).

## Developer fixtures

```zsh
FX=/tmp/flux-fixtures
cargo run -p flux --example make-fixtures -- $FX
ls $FX
```

The lab gate **G1** uses `udp-basic.pcap` from that directory.

## Batch replay (no TTY)

```zsh
cargo build -p flux
cargo run -p flux -- watch -r $FX/udp-basic.pcap '+views=src,qtype,2'
```

## Live capture (G1 step 4)

```zsh
cargo build -p flux
sudo ./target/debug/flux watch -i lo
```

Generate DNS in another terminal (e.g. `dig @127.0.0.53 example.com`). The TUI drains
`AF_PACKET` on each frame; status `packets=` should increase. Loopback often delivers
IP frames without Ethernet — decode tries `from_ip` when `from_ethernet` fails.

## Tests

```zsh
cargo test -p flux
```