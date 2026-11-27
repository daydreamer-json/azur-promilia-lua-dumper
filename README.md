# azur-promilia-lua-dumperer

A Lua dumper for Azur Promilia. For myself.

## Usage

```sh
cargo build --release
./target/release/azur-promilia-lua-dumper static --res <StreamingAssets/.res/raw_nostreaming_package> --out out/
```

With decompilation (built in, no extra tools needed):

```sh
./target/release/azur-promilia-lua-dumper static --res <res> --out out/ --decompile
```

From a running process:

```sh
./target/release/azur-promilia-lua-dumper mem --pid <pid> --out out_mem/
```

## Notes

- The Lua bodies live in `raw_nostreaming_package` (XOR 0x40, 128-byte signature, Lua 5.3 bytecode).
- Signatures are verified with the Lua-side RSA key. Module trees (`src/...`) are restored from chunk names.
- Bytecode is decompiled with the bundled unluac-rs engine (`--decompile`).
- UnityCN-encrypted bundles (e.g. default_package) cannot be opened without the key; only carving is done.
