# BadMemoryList

BadMemoryList is a small Python utility for analyzing MemTest86 logs, identifying suspect Page Frame Numbers (PFNs), merging them with an optional initial list of bad PFNs, and exporting a Windows-compatible bad-memory list.

## Overview

The script scans MemTest86 log lines such as:

```text
[MEM ERROR - Data] Test: 1, CPU: 0, Address: ABCD, Expected: 1, Actual: 0
[MEM WARNING] Test: 1, CPU: 0, Address: 2000, Expected: 1, Actual: 0
```

Address and data values are hexadecimal and must not include a `0x` prefix. For
each matching issue, the script:

- extracts the physical address,
- converts the byte address to a PFN using the standard 4 KiB page size,
- groups findings by PFN,
- keeps already-known bad PFNs when an initial file is provided,
- prioritizes `ERROR` over `WARNING` when building the final state,
- prints a compact summary and full-resolution status map,
- writes the final bad-memory PFN list,
- optionally generates a detailed JSON report and a Windows `bcdedit` script.

The calculated PFN status range contains one cell per PFN in the inclusive
range; gaps are shown as `OK`. `display_pfn_status_range` accepts `line_size`
and an optional `max_lines`. When `max_lines` is set, adjacent PFNs are grouped
into display cells as needed so the entire range fits without omitting any
PFNs; the calculated range remains full-resolution.

## Project files

- `badmemorylist.py` : main CLI script used to parse the log and produce outputs
- `Get-BadMemory.ps1` : PowerShell helper that reads the current bad-memory value from `bcdedit`
- `LICENSE` : project license

## Requirements

- Python 3.10+
- a MemTest86 log as a text file
- optionally, a text file containing PFNs already known to be bad

## Input formats

### MemTest86 log

The parser matches log lines in the standard MemTest86 format and expects these fields:

- `Test`
- `CPU`
- `Address`
- `Expected`
- `Actual`

### Initial bad-memory list

The optional initial list should contain one hexadecimal PFN per line. The `0x` prefix is optional, for example:

```text
0x123
0x456
0xABC
```

## Usage

```bash
python3 badmemorylist.py -m memtest.log -f badmemorylist_initial.txt -r -s
# Write only the text list
python3 badmemorylist.py -m memtest.log -b
```

Replace the example file names with the paths to your files. Relative and
absolute paths are accepted; generated files are written to the current
directory by default.

On Windows, you can also use the current bad-memory store directly instead of a local file:

```bash
python3 badmemorylist.py -m memtest.log -w -r -s
# or
python3 badmemorylist.py -m memtest.log --windows-initial -r -s
```

To update the Windows bad-memory store directly, use `-u` or
`--update-windows` instead of `-s` or `--script`:

```bash
python3 badmemorylist.py -m memtest.log -w -u
```

This replaces the Windows list with the PFNs calculated by the run. Use `-w` to
include the current Windows list in those PFNs. The command requires an
elevated Windows terminal and refuses to update the store if no PFNs were
calculated. The `-b` option can also be added to save the text list during this
update.

At least one output action is required: `-b`, `-s`, or `-u`. The text list can
be combined with either the script or direct Windows update; `-s` and `-u`
cannot be used together. The report option `-r` is additional and does not
satisfy this requirement by itself.

### Command-line options

- `-m, --memtest-log` : path to the MemTest86 log file to analyze
- `-f, --file-initial` : optional file containing PFNs already classified as bad
- `-w, --windows-initial` : read the initial PFN list from the current Windows `{badmemory}` store; exclusive with `--file-initial`
- `-o, --output` : output directory where generated files are written (default: `./`)
- `--force` : remove existing selected output files before creating them
- `-r, --report` : generate a detailed JSON report named `badmemory_reports.json`
- `-b, --write-list` : write the final PFN list to `badmemorylist.txt`; required unless `--script` or `--update-windows` is selected
- `-s, --script` : generate a Windows batch script named `badmemorylist.bat`; exclusive with `--update-windows`
- `-u, --update-windows` : update the Windows `{badmemory}` store directly; requires administrator privileges and is exclusive with `--script`

## Generated outputs

Depending on the selected output options, the script can write:

- `badmemorylist.txt` : one PFN per line, formatted as hexadecimal values (`--write-list`)
- `badmemory_reports.json` : detailed state report with PFN metadata, issue lists, and the severity of each entry (`--report`)
- `badmemorylist.bat` : a Windows batch file containing the `bcdedit /set {badmemory} badmemorylist ...` command (`--script`)

The `--update-windows` option updates the Windows store directly and does not
create a batch file. It can be combined with `--write-list`.
Use `--force` to replace only the selected generated output files in the output
directory; other files are left untouched.

## Example output

```text
===== BAD MEMORY ANALYSIS =====
Initial PFNs     : 12
New PFNs errors  : 3
New PFNs warnings: 1
New PFNs issues  : 4
Total PFNs issues: 16

===== PFN STATUS MAP =====
PFN range 0x100-0x10F; 1 PFN per cell
.E....W.........
Legend: E=error W=warning .=OK (priority: E > W > .)
```

## Notes

- The script treats PFNs already listed in the initial file as existing bad memory and begins them in the `ERROR` state.
- PFNs found only in the log start in the `WARNING` state and are promoted to `ERROR` if at least one log entry is an error.
- Output files are created in the selected output directory. Existing files are
  preserved unless `--force` is specified.

## License

This project is distributed under the MIT License. See the `LICENSE` file for details.
