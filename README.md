# Kebabfuscator Deobfuscator

A static Python deobfuscator for **Kebabfuscator v1** — a Lua/Luau obfuscator that wraps scripts inside a custom virtual machine and encrypts string tables. This tool recovers the original logic without executing the obfuscated code.

---

## What It Does

Kebabfuscator v1 protects Lua/Luau scripts by:

1. **Encrypting all string literals** into an encoded table decoded at runtime.
2. **Compiling the entry chunk** into a custom bytecode format and embedding a VM interpreter inline.
3. **Randomizing identifiers** on every run so variable names change each time the script is generated.

This deobfuscator reverses all three layers statically:

- Reconstructs the encrypted string tables and replaces decode loops with plain Lua assignments.
- Decodes the embedded VM bytecode stream and maps it back to Luau source.
- Canonicalizes per-run randomized identifiers so the output is consistent across obfuscation runs.

**No Lua interpreter is invoked at any point.** The input is analyzed as text.

---

## Modes

| Mode | Flag | What you get |
|---|---|---|
| **Default** | *(none)* | String tables recovered; VM wrapper retained |
| **Lift** | `--lift` | Full decompilation — VM bytecode lifted to readable Luau |
| **Anti-tamper** | `--antitamper` | The entry chunk's anti-tamper closure extracted as a standalone Lua module |

The three modes are mutually exclusive.

---

## Quick Start

**Requirements:** Python 3.8 or newer. No third-party packages — standard library only.

```bash
# Recover string tables only (fast, conservative)
python deobfuscator/deobfuscator.py samples/sample.lua

# Full lift to readable Luau
python deobfuscator/deobfuscator.py samples/sample.lua --lift

# Extract the anti-tamper closure
python deobfuscator/deobfuscator.py samples/sample.lua --antitamper -o out/sample.antitamper.lua

# Process an entire folder of .lua files
python deobfuscator/deobfuscator.py my_folder/ --lift
```

Output is written beside the input file by default:

| Input | Mode | Output |
|---|---|---|
| `sample.lua` | default | `sample.deobfuscated.lua` |
| `sample.lua` | `--lift` | `sample.lifted.lua` |
| `sample.lua` | `--antitamper` | `sample.antitamper.lua` |

Use `-o <path>` to override the output location.

Every generated file begins with:
```lua
-- oh my days deobfuscated this obfuscator with this special deobfuscator so insane
```

---

## Project Layout

```
deobfuscator/
    deobfuscator.py      CLI entry point and static pipeline orchestrator
    keb.py               Constants extraction and string-table decoding
    names.py             Per-run identifier canonicalization
    vm.py                VM bytecode decoding
    newdeob.py           Expression reconstruction helpers
    lift.py              VM-to-Luau lifter
    opcode_map.txt       Diagnostic / legacy opcode reference

samples/
    sample.lua                       Compact Kebabfuscator v1 sample
    sample beautified.lua            Formatted variant of the same sample
    samplekebab.txt_obf (2).lua      Randomized-identifier regression input
    antitamper.lua                   Extracted anti-tamper module example
    harness2.lua                     Lua 5.1 compatibility harness
    lifted_main.lua                  Harness-adapted lifted output
    mz_oracle.json                   Recorded loader comparison data

tests/
    test_deobfuscator.py   End-to-end deobfuscation regression tests
    test_lifter.py         VM lifter tests
    test_decode.py         String-table decoder tests
    test_loader.py         Loader/constants extraction tests
    test_all.py            Diagnostic runner
    run_tests.bat          Windows shortcut: full unittest suite
    runlua.bat             Windows shortcut: Lua 5.1 harness
```

---

## Running the Tests

```bash
# Full unittest suite (from project root)
python -m unittest discover -s tests -v

# Individual diagnostics
python tests/test_all.py
python tests/test_decode.py
python tests/test_loader.py
```

On Windows, `tests/run_tests.bat` runs the full suite and `tests/runlua.bat` launches the Lua 5.1 harness.

---

## Limitations and Scope

- Targets **Kebabfuscator v1** specifically. Other versions or modified outputs may not be recognized and will be reported as errors — the tool never silently passes through unprocessed input.
- The lifted output is **Luau**, not plain Lua 5.1. It may use Roblox APIs (`game`, `workspace`, etc.) and Luau syntax (`//` integer division). Use a Luau runtime in a Roblox context, or manually adapt the output.
- The included Lua 5.1 harness (`harness2.lua`) is a semantic smoke test for the bundled sample only — it is not a general compatibility shim.
- Identifier randomization is handled automatically; per-run name changes alone do not require any manual configuration.

---

## Anti-Tamper Note

The `--antitamper` mode **extracts** the detected closure; it does not disable, bypass, or remove the checks inside it. The extracted function's behavior — accessing Roblox services, creating/destroying parts, physics probes — is preserved exactly. It is returned by the module but not called automatically.

Inspect the module before requiring or calling it. Extraction is intended for analysis and authorized reuse, not as a safety guarantee.

---

## Troubleshooting

| Error | Cause | Fix |
|---|---|---|
| `input does not exist` | Bad path | Check the path; relative paths resolve from cwd |
| `input is not valid UTF-8` | Non-UTF-8 file | Re-save the source as UTF-8 (BOM is accepted) |
| `Unsupported source` / opcode errors | Input doesn't match Kebabfuscator v1 structure | May be a different version or configuration |
| Lifted output fails in Lua 5.1 | Output is Luau syntax | Use a Luau runtime; see *Limitations* above |
