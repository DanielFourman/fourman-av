# Fourman AV — SHA-256 signature scanner

A small, educational antivirus:

- **`scanner.c`** — the scanning engine, written in C. It loads known-bad
  SHA-256 hashes from an abuse.ch / MalwareBazaar CSV export, recursively
  hashes every file in a folder, and **moves matches into a quarantine folder**.
- **`antivirus_gui.py`** — a Tkinter GUI: pick a folder, watch a **progress
  bar**, read a **live log**, see **scanned / detected counters**, and update
  the signature database.
- **`FourmanAV/`** — a prebuilt, ready-to-run copy of the GUI (packaged with
  PyInstaller) plus `scanner.exe` and a `recent.csv` signature snapshot. No
  Python or C compiler required — see [Quick start](#quick-start-no-build-required).

It is signature-based only (exact hash match). It will **not** catch anything
that isn't already in the database, and is meant for learning, not as a
replacement for a real AV.

---

## Quick start (no build required)

1. Copy the whole `FourmanAV/` folder anywhere.
2. Double-click `FourmanAV.exe`.
3. Pick a folder to scan and click **Start scan**.

`recent.csv` (the signature database) and `scanner.exe` (the engine) are
already bundled next to it, so this works immediately — no Auth-Key needed
unless you want to refresh the database (see below).

> **Heads up:** this is an unsigned executable that scans and moves files —
> exactly the behavior antivirus heuristics look for. Norton, Defender, etc.
> may flag or block it on first run. If that happens, add `FourmanAV.exe` (or
> the whole `FourmanAV` folder) as an exclusion in your AV settings.

---

## Building from source

You need a C compiler. If you don't have one:

```powershell
winget install -e --id BrechtSanders.WinLibs.POSIX.UCRT   # provides gcc
```

Then, from this folder:

```powershell
.\build.bat
```

This produces `scanner.exe` next to the sources. You can also compile manually:

```powershell
gcc -O2 -Wall -o scanner.exe scanner.c
```

Run the GUI with:

```powershell
python antivirus_gui.py
```

(Requires Python 3 with Tkinter, which ships with the standard python.org
Windows installer.)

### Rebuilding the packaged exe

```powershell
pip install pyinstaller
pyinstaller --onedir --windowed --name FourmanAV antivirus_gui.py
```

Then copy `scanner.exe` and `recent.csv` into the generated `FourmanAV/` output
folder so the packaged app can find them.

---

## Updating the signature database

`recent.csv` in this repo is a snapshot — it goes stale. To refresh it:

1. Get a free Auth-Key at <https://auth.abuse.ch/>.
2. Launch the GUI, paste the key in the **Auth-Key** field, click
   **Update database**. It runs:

   ```
   curl -sS -L -H "Auth-Key: <KEY>" -o recent.csv \
        "https://mb-api.abuse.ch/v2/files/exports/<KEY>/recent.csv"
   ```

   and saves `recent.csv` here.

The engine is tolerant about the file format: any 64-hex-character token in the
CSV is treated as a SHA-256 signature, so both the quoted MalwareBazaar layout
and a plain "one hash per line" file work.

## Running from source (command line, no GUI)

```powershell
scanner.exe recent.csv "C:\path\to\scan" ".\quarantine"
```

The engine prints one record per line: `HASHES`, `TOTAL`, `SCAN`, `PROGRESS`,
`CLEAN`, `DETECT`, `QUARANTINE`, `ERROR`, `DONE` — this is what the GUI parses.

The engine skips the quarantine folder while scanning so it never re-scans
files it just quarantined.

---

## Test it safely

To confirm detection works without real malware, add a file's own hash to the
database and scan it:

```powershell
# make a harmless test file
"hello world" | Out-File -Encoding ascii testfile.txt
# compute its SHA-256 and append to the database
(Get-FileHash testfile.txt -Algorithm SHA256).Hash.ToLower() | Add-Content recent.csv
# scan the folder containing it -> it should be detected and quarantined
scanner.exe recent.csv . .\quarantine
```

Or use the standard **EICAR** test string, whose SHA-256 is published, if you
prefer a real AV test vector.

---

## Notes / limitations

- Signature (hash) matching only — no heuristics, no unpacking, no memory scan.
- Quarantine = a plain move with a hash prefix in the filename; files are not
  encrypted or neutralised, just relocated. Don't rely on it for real threats.
- `recent.csv` from abuse.ch contains only *recent* submissions; it is a small
  sample, not the full corpus.
- If you scan a folder that your antivirus actively protects (Desktop,
  Documents, etc. under Norton/Defender Controlled Folder Access), the
  quarantine *move* can silently fail even though detection succeeds — the AV
  blocks the delete/rename. Add an exclusion for the scan/quarantine folders
  if you hit this.
