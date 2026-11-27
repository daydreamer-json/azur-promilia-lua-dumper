# azur-promilia-lua-dumper

A Lua dumper for Azur Promilia. For myself.

## What it does

Extracts signed Lua 5.3 bytecode from YooAsset raw packages, verifies the
RSA-1024 + SHA1 signature, restores the module tree from chunk names, and
decompiles with the bundled unluac-rs engine. No external tools needed.

## Usage

```sh
cargo build --release
./target/release/azur-promilia-lua-dumper static --res <StreamingAssets/.res/raw_nostreaming_package> --out out/
```

```sh
# with decompilation
./target/release/azur-promilia-lua-dumper static --res <res> --out out/ --decompile

# read-only scan of a running process (no ptrace, no key dumping)
./target/release/azur-promilia-lua-dumper mem --pid <pid> --out out_mem/

# recover the UnityCN bundle password from header vectors (static scan)
./target/release/azur-promilia-lua-dumper recover-key --bundle <a.r> --scan <file>...
```

## Output

- `out/<category>/<path>.lub` — signature-stripped bytecode (e.g. `src/...`, `configShell/...`)
- `out/<category>/<path>.lua` — decompiled source (`--decompile`)
- `out/_raw/*.json` — unsigned config files
- `out/_carve/...` — fragments carved from encrypted bundles
- `out/manifest.json` — sha256, signature status, module names per file

## Notes

- Signatures are verified with the Lua-side RSA key.
- UnityCN-encrypted bundles (e.g. default_package) cannot be opened without
  the key; only carving is attempted.
