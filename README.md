# kasada-vm

Browserless Kasada solver. Runs the `p.js` fingerprint VM in a Node sandbox and pulls a real,
server-valid `x-kpsdk-ct` off `/tl`.

## What it does

- mints `x-kpsdk-ct` from the `/tl` fingerprint blob (the hard part), server returns 200
- `x-kpsdk-h` from `/mfc`
- tooling to dump, crack and disassemble any `p.js` version: bytecode (67k ints), the full
  string table, and the cd/PoW region

## Usage

```
npm i
REAL=1 PROXY=host:port:user:pass node run-decomp.mjs
```

`ct` is tied to the IP, UA and TLS it was generated on, so replay it through the same session.
Without `REAL`/`PROXY` it runs offline and just logs what the VM sends.

## cd

`x-kpsdk-cd` (the per-request PoW) is the WIP. Groundwork's here: bytecode decoded, string
table cracked, PoW mechanics mapped (sha256, ~2 rounds, threshold 5). What's left is lifting
the parent-side VM out of `p.js`, since the seed mixes a value that never hits the wire. The
`cd/` scripts show what's been ruled out. PRs welcome.

## Layout

- `run-decomp.mjs` runs the VM and mints `ct`
- `tools/` dump, crack strings, disassemble, find the cd region
- `cd/` the cd PoW work
- `dump/` decoded artifacts (bytecode, cipher map, strings), no tokens
- `Emrovsky/` the decompiled VM + Rust lifter, by Emrovsky

Bring your own `p.js` capture; scripts take a path arg or read a local `_vm-traces/`
(gitignored). Don't commit tokens or proxies.

## Credits

`Emrovsky/decomp.js` and `leak.rs` by Emrovsky. Disasm approach from umasi's nullpt.rs
Nike/Kasada writeup. Other refs: `Thoosje/Kasada`, `infectrs/kasada`, `Sud0Krypt/kasada-reverse`.

## Notes

Research and educational. Kasada is commercial, use it where you're allowed to.
