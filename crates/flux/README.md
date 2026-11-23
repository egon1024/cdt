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

## Tests

```zsh
cargo test -p flux
```