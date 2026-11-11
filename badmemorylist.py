#!/usr/bin/env python3

import argparse
import json
import math
import os
import re
import subprocess
import sys
from dataclasses import dataclass
from enum import IntEnum
from pathlib import Path

# MemTest86 byte addresses are converted to PFNs using 4 KiB pages.
PFN_PAGE_SIZE = 4 * 1024

# Reuse the compiled pattern across calls; this has little impact in a one-shot run.
_MEMTEST_ISSUE_PATTERN = re.compile(
    r"\[MEM (ERROR|WARNING)(?: - Data)?\] "
    r"Test: (\d+), "
    r"CPU: (\d+), "
    r"Address: ([0-9a-fA-F]+), "
    r"Expected: ([0-9a-fA-F]+), "
    r"Actual: ([0-9a-fA-F]+)",
    re.IGNORECASE,
)


class PfnStatus(IntEnum):
    """Status codes assigned to a page frame number."""

    OK = 0
    ERROR = 1
    WARNING = 2


# ANSI foreground color codes used for each status in the terminal map.
_STATUS_COLORS: dict[PfnStatus, str] = {
    PfnStatus.OK: "32",
    PfnStatus.WARNING: "33",
    PfnStatus.ERROR: "31",
}

# Single-character markers used for each status in the compact map.
_STATUS_SYMBOLS: dict[PfnStatus, str] = {
    PfnStatus.OK: ".",
    PfnStatus.WARNING: "W",
    PfnStatus.ERROR: "E",
}


@dataclass(frozen=True)
class MemtestIssue:
    """A parsed MemTest86 issue record.

    Attributes:
        address (int): Reported physical byte address.
        severity (PfnStatus): Error or warning reported by MemTest86.
        test (int): MemTest86 test number.
        cpu (int): CPU number that reported the issue.
        expected (int): Expected memory value.
        actual (int): Actual memory value.
    """

    address: int
    severity: PfnStatus
    test: int
    cpu: int
    expected: int
    actual: int

    def to_json_dict(self) -> dict[str, object]:
        """Serialize this issue for JSON export.

        Returns:
            dict[str, object]: JSON-compatible issue fields.
        """
        return {
            "address": f"0x{self.address:X}",
            "severity": self.severity.name,
            "test": self.test,
            "cpu": self.cpu,
            "expected": f"0x{self.expected:X}",
            "actual": f"0x{self.actual:X}",
        }


@dataclass
class PfnState:
    """State information for a single PFN.

    Attributes:
        exists (bool): Whether the PFN was present in the initial bad-memory list.
        status (PfnStatus): Aggregated status for the PFN.
        reports (list[MemtestIssue]): MemTest86 issues associated with the PFN.
    """

    exists: bool
    status: PfnStatus
    reports: list[MemtestIssue]

    def to_json_dict(self) -> dict[str, object]:
        """Serialize this PFN state for JSON export.

        Returns:
            dict[str, object]: JSON-compatible PFN state and issue records.
        """
        return {
            "exists": self.exists,
            "status": self.status.name,
            "reports": [report.to_json_dict() for report in self.reports],
        }


@dataclass(frozen=True)
class PfnStats:
    """Summary counts for the analyzed PFN set.

    Attributes:
        initial_count (int): PFNs already present in the initial list.
        new_error_count (int): Newly discovered PFNs with error status.
        new_warning_count (int): Newly discovered PFNs with warning status.
        new_issue_count (int): Total newly discovered PFNs.
        total_count (int): Total PFNs in the combined state mapping.
    """

    initial_count: int
    new_error_count: int
    new_warning_count: int
    new_issue_count: int
    total_count: int


@dataclass(frozen=True)
class PfnStatusRange:
    """Full-resolution statuses for a contiguous PFN range.

    Attributes:
        min_pfn (int): Lowest PFN represented.
        max_pfn (int): Highest PFN represented.
        cells (list[PfnStatus]): Status of each PFN in the range.
    """

    min_pfn: int
    max_pfn: int
    statuses: list[PfnStatus]


def read_pfns_from_file(file: Path) -> set[int]:
    """Read a PFN list stored as one value per line.

    The input file is expected to contain hexadecimal page-frame numbers, one per
    line, optionally prefixed with ``0x``. Values are normalized to integers and
    returned as a unique set.

    Args:
        file (Path): Path to the PFN list file.

    Raises:
        FileNotFoundError: If the file does not exist.
        ValueError: If a line cannot be parsed as a hexadecimal integer.

    Returns:
        set[int]: The unique PFNs discovered in the input file.
    """
    if not file.exists():
        raise FileNotFoundError(f"Error: File '{file}' does not exist.")

    lines = file.read_text(encoding="utf-8").splitlines()

    return {int(line, 16) for line in lines}


def read_pfns_from_windows() -> set[int]:
    """Read the current Windows bad-memory list from ``bcdedit``.

    This helper is only valid on Windows, where the OS keeps the bad-memory
    entries in the ``{badmemory}`` store. The returned values are normalized to
    PFN integers and deduplicated.

    Raises:
        OSError: If the current platform is not Windows or if ``bcdedit`` cannot
            provide the bad-memory list.

    Returns:
        set[int]: The PFNs already present in the Windows bad-memory store.
    """
    if os.name != "nt":
        raise OSError("Windows bad-memory list can only be read on Windows.")

    cmd = "bcdedit /enum {badmemory}"
    result = subprocess.run(cmd, capture_output=True, text=True, check=False)

    if result.returncode != 0:
        stderr = result.stderr.strip() or result.stdout.strip() or "unknown error"
        raise OSError(f"Failed to read the Windows bad-memory list: {stderr}")

    pfns = set()
    for line in result.stdout.splitlines():
        value = line.strip()
        if value.startswith("0x"):
            pfns.add(int(value, 16))

    return pfns


def get_memtest_issue(line: str) -> MemtestIssue | None:
    """Parse a single MemTest86 memory issue line.

    The log format is expected to look like:
    ``[MEM ERROR] Test: 1, CPU: 0, Address: ABCD, Expected: 1, Actual: 0``
    or the corresponding ``WARNING`` variant. Address and data values are
    hexadecimal and must not include a ``0x`` prefix.

    Args:
        line (str): One line from a MemTest86 log.

    Returns:
        MemtestIssue | None: The parsed issue data, or ``None`` when the line
        does not match the supported MemTest86 issue format.
    """
    match = _MEMTEST_ISSUE_PATTERN.search(line)
    if not match:
        return None

    return MemtestIssue(
        address=int(match.group(4), 16),
        severity=PfnStatus[match.group(1).upper()],
        test=int(match.group(2)),
        cpu=int(match.group(3)),
        expected=int(match.group(5), 16),
        actual=int(match.group(6), 16),
    )


def parse_memtest_issues(
    file: Path,
) -> dict[int, list[MemtestIssue]]:
    """Parse a MemTest86 log and group each issue by PFN.

    The parser matches lines such as ``[MEM ERROR] Test: 1, CPU: 0, Address: ...``
    and converts the reported byte address to a page-frame number by shifting it
    right by 12 bits, which corresponds to the standard 4 KiB page size.

    Args:
        file (Path): Path to the MemTest86 log file.

    Raises:
        FileNotFoundError: If the log file does not exist.

    Returns:
        dict[int, list[MemtestIssue]]: PFNs mapped to their collected issue
            records.
    """
    if not file.exists():
        raise FileNotFoundError(f"Error: File '{file}' does not exist.")

    issues: dict[int, list[MemtestIssue]] = {}
    page_shift = PFN_PAGE_SIZE.bit_length() - 1

    # Process the log line by line to avoid loading the whole file into memory.
    with file.open(encoding="utf-8", errors="replace") as log_file:
        for line in log_file:
            issue = get_memtest_issue(line)

            if not issue:
                continue

            # MemTest86 reports byte addresses; a 4 KiB page corresponds to a 12-bit shift.
            pfn = issue.address >> page_shift

            issues.setdefault(pfn, []).append(issue)

    return issues


def build_pfn_states(
    log_file: Path, pfns_initial: set[int] | None
) -> dict[int, PfnState]:
    """Merge a known bad-PFN list with MemTest86 findings.

    PFNs supplied in the initial file are considered already known bad memory and
    start in the ``ERROR`` state. PFNs discovered only in the log begin in the
    ``WARNING`` state and are promoted to ``ERROR`` when a log entry marks them as
    an error.

    Args:
        log_file (Path): Path to the MemTest86 log.
        pfns_initial (set[int] | None): PFNs already present in an initial
            bad-memory list, or ``None`` when no initial list is supplied.

    Returns:
        dict[int, PfnState]: PFNs mapped to their status, whether each PFN was
            already present in the initial list, and its associated reports.
    """
    page_issues = parse_memtest_issues(log_file)

    # PFNs already listed are known bad memory and begin in the ERROR state.
    pfns = pfns_initial or set()
    page_states = {
        pfn: PfnState(exists=True, status=PfnStatus.ERROR, reports=[]) for pfn in pfns
    }

    # PFNs that are only discovered in the log start as WARNING, and a single
    # ERROR issue promotes them to ERROR without downgrading later WARNINGS.
    for pfn, issues in page_issues.items():
        state = page_states.setdefault(
            pfn,
            PfnState(exists=False, status=PfnStatus.WARNING, reports=[]),
        )
        state.reports.extend(issues)

        has_error = any(issue.severity == PfnStatus.ERROR for issue in issues)
        if state.status != PfnStatus.ERROR and has_error:
            state.status = PfnStatus.ERROR

    return page_states


def calculate_stats(page_states: dict[int, PfnState]) -> PfnStats:
    """Calculate summary counts for the analyzed PFNs.

    Args:
        page_states (dict[int, PfnState]): PFN state mapping produced by
            ``build_pfn_states``.

    Returns:
        PfnStats: Summary counts for initial PFNs, newly detected errors and
            warnings, all newly detected PFNs, and the total PFN count.
    """
    initial_count = sum(state.exists for state in page_states.values())
    new_error_count = sum(
        not state.exists and state.status == PfnStatus.ERROR
        for state in page_states.values()
    )
    new_warning_count = sum(
        not state.exists and state.status == PfnStatus.WARNING
        for state in page_states.values()
    )

    return PfnStats(
        initial_count=initial_count,
        new_error_count=new_error_count,
        new_warning_count=new_warning_count,
        new_issue_count=new_error_count + new_warning_count,
        total_count=len(page_states),
    )


def build_pfn_status_range(
    page_states: dict[int, PfnState],
) -> PfnStatusRange | None:
    """Build a full-resolution status range from the PFN states.

    The returned range has one cell per PFN in the inclusive range. PFNs absent
    from the input mapping are treated as ``OK``.

    Args:
        page_states (dict[int, PfnState]): PFN state mapping produced by
            ``build_pfn_states``.

    Returns:
        PfnStatusRange | None: The minimum and maximum PFN and the status of
            every PFN in the range, or ``None`` when the input mapping is empty.
    """
    if not page_states:
        return None

    pfn_min = min(page_states)
    pfn_max = max(page_states)
    pfn_span = pfn_max - pfn_min + 1
    statuses = [PfnStatus.OK] * pfn_span

    for pfn, state in page_states.items():
        statuses[pfn - pfn_min] = state.status

    return PfnStatusRange(
        min_pfn=pfn_min,
        max_pfn=pfn_max,
        statuses=statuses,
    )


def display_stats(stats: PfnStats) -> None:
    """Print the summary counts for the analyzed PFNs.

    The output includes the number of PFNs already known to be bad, the number of
    newly detected error and warning PFNs, and the total PFN count.

    Args:
        stats (PfnStats): PFN statistics to display.

    Returns:
        None
    """
    print("\n===== BAD MEMORY ANALYSIS =====")
    print(f"Initial PFNs     : {stats.initial_count}")
    print(f"New PFNs errors  : {stats.new_error_count}")
    print(f"New PFNs warnings: {stats.new_warning_count}")
    print(f"New PFNs issues  : {stats.new_issue_count}")
    print(f"Total PFNs issues: {stats.total_count}")


def display_pfn_status_range(
    status_range: PfnStatusRange | None,
    line_size: int = 64,
    max_lines: int = 64,
    use_colors: bool = True,
) -> None:
    """Print the PFN status range, grouping cells to fit the line limit.

    Args:
        status_range (PfnStatusRange | None): PFN status range to display, or
            ``None`` when there are no PFNs.
        line_size (int): Maximum number of status cells to print per
            line. Defaults to ``64``.
        max_lines (int): Maximum number of map lines. When set, adjacent
            PFNs are grouped into a single display cell as needed to fit the
            complete map. Defaults to ```64``.
        use_colors (bool): Colorize status at display.

    Raises:
        ValueError: If ``line_size`` or a specified ``max_lines`` is not
            positive.

    Returns:
        None
    """
    if line_size <= 0:
        raise ValueError("line_size must be a positive integer.")

    if max_lines <= 0:
        raise ValueError("max_lines must be a positive integer.")

    def colorize(status: PfnStatus) -> str:
        if not use_colors:
            return _STATUS_SYMBOLS[status]
        return f"\033[{_STATUS_COLORS[status]}m{_STATUS_SYMBOLS[status]}\033[0m"

    print("\n===== PFN STATUS MAP =====")
    if status_range is None:
        print("No PFNs to display.")
        return

    status_count = len(status_range.statuses)
    max_display_cells = line_size * max_lines
    pfns_per_cell = max(1, math.ceil(status_count / max_display_cells))

    display_cells = []
    for start in range(0, status_count, pfns_per_cell):
        group = status_range.statuses[start : start + pfns_per_cell]
        if PfnStatus.ERROR in group:
            display_cells.append(PfnStatus.ERROR)
        elif PfnStatus.WARNING in group:
            display_cells.append(PfnStatus.WARNING)
        else:
            display_cells.append(PfnStatus.OK)

    text_res = (
        f"{pfns_per_cell} PFN"
        if pfns_per_cell == 1
        else f"up to {pfns_per_cell} PFNs per cell"
    )
    text_range = f"PFN range 0x{status_range.min_pfn:X}-0x{status_range.max_pfn:X}"
    print(f"{text_range}; {text_res}")

    for line in range(0, len(display_cells), line_size):
        first_pfn = status_range.min_pfn + line * pfns_per_cell
        cells = display_cells[line : line + line_size]

        print(f"0x{first_pfn:X}: " + "".join(colorize(status) for status in cells))

    print(
        f"Legend: {colorize(PfnStatus.ERROR)}=error "
        f"{colorize(PfnStatus.WARNING)}=warning "
        f"{colorize(PfnStatus.OK)}=OK (priority: E > W > .)"
    )


def _prepare_output_file(output: Path, force: bool) -> None:
    """Remove an existing output file when forced; otherwise refuse to replace it."""
    if not output.exists():
        return

    if not force:
        raise FileExistsError(f"Error: File '{output}' already exists.")

    output.unlink()


def write_report(
    page_states: dict[int, PfnState],
    output: Path = Path("./reports.txt"),
    force: bool = False,
) -> None:
    """Write the detailed PFN-state report as JSON.

    The export is intended for review and debugging: PFN keys are written in
    hexadecimal form, the status is stored as the enum name, and all expected and
    actual memory values are formatted as hexadecimal strings.

    Args:
        page_states (dict[int, PfnState]): Mapping of PFNs to state metadata.
        output (Path): Destination path for the JSON report. Defaults to
            ``./reports.txt``.
        force (bool): Remove an existing output file before writing.

    Raises:
        FileExistsError: If the destination exists and ``force`` is false.

    Returns:
        None
    """
    _prepare_output_file(output, force)

    results = {
        hex(pfn): state.to_json_dict() for pfn, state in sorted(page_states.items())
    }

    json_str = json.dumps(results, indent=4, ensure_ascii=False)
    output.write_text(json_str, encoding="utf-8")


def write_badmemory_list(
    pfns: list[int],
    output: Path = Path("./badmemorylist.txt"),
    force: bool = False,
) -> None:
    """Write the final PFN list as a plain text file.

    Each PFN is exported as a hexadecimal value, one per line, so the output can
    be consumed by Windows memory-blacklisting tools or by downstream automation.

    Args:
        pfns (list[int]): PFN integers to export.
        output (Path): Destination path; defaults to ``./badmemorylist.txt``.
        force (bool): Remove an existing output file before writing.

    Raises:
        FileExistsError: If the destination exists and ``force`` is false.

    Returns:
        None
    """
    _prepare_output_file(output, force)

    output.write_text("\n".join(hex(pfn) for pfn in pfns), encoding="utf-8")


def build_bcdedit_command(pfns: list[int]) -> str:
    """_summary_

    Args:
        pfns (list[int]): _description_

    Returns:
        str: _description_
    """
    pfns_str = " ".join(hex(pfn) for pfn in pfns)
    return f"bcdedit /set {{badmemory}} badmemorylist {pfns_str}"


def write_bcdedit_script(
    cmd: str,
    output: Path = Path("./update_badmemorylist.bat"),
    force: bool = False,
) -> None:
    """Write a ``bcdedit`` command for setting the Windows bad-memory store.

    The generated batch command uses the ``{badmemory}`` store and includes every
    PFN in the final list so it can be used on a Windows system when updating the
    memory blacklist.

    Args:
        pfns (list[int]): PFN integers to include in the command.
        output (Path): Destination path; defaults to
            ``./update_badmemorylist.bat``.
        force (bool): Remove an existing output file before writing.

    Raises:
        FileExistsError: If the destination exists and ``force`` is false.

    Returns:
        None
    """
    _prepare_output_file(output, force)

    output.write_text(cmd, encoding="utf-8")


def launch_windows_command(cmd: str) -> None:
    """Replace the Windows bad-memory list with the supplied PFNs.

    Args:
        pfns (list[int]): PFNs to write to the Windows bad-memory store.

    Raises:
        OSError: If called outside Windows or if ``bcdedit`` cannot update the
            store.
        ValueError: If ``pfns`` is empty.

    Returns:
        None
    """
    if os.name != "nt":
        raise OSError("Windows bad-memory list can only be updated on Windows.")

    if not cmd:
        raise ValueError("Cannot update the Windows bad-memory list with no PFNs.")

    result = subprocess.run(cmd, capture_output=True, text=True, check=False)
    if result.returncode != 0:
        stderr = result.stderr.strip() or result.stdout.strip() or "unknown error"
        raise OSError(f"Failed to update the Windows bad-memory list: {stderr}")


def parse_args(args: list[str] | None = None) -> argparse.Namespace:
    """Parse the command-line arguments for the MemTest86 analysis workflow.

    The CLI accepts a MemTest86 log, optionally includes a file of already-known
    bad PFNs, and can write the bad-memory list, generate a JSON report, generate
    a Windows ``bcdedit`` script, or update the Windows bad-memory list directly.

    Args:
        args (list[str] | None): Optional argument list; defaults to the
            current process command line.

    Returns:
        argparse.Namespace: Parsed options including the log path, optional
            initial PFN file or Windows source, output directory, report flag,
            bad-memory-list output flag, script flag, force flag, and direct
            Windows-update flag.
    """
    parser = argparse.ArgumentParser(
        description=(
            "Analyze a MemTest86 log, merge it with any pre-existing bad-PFN list, "
            "display the detected status, and generate the corresponding bad-memory "
            "outputs."
        ),
        epilog=(
            "Examples:\n"
            "  python3 badmemorylist.py -l memtest.log "
            "-f badmemorylist_initial.txt -r -s\n"
            "  python3 badmemorylist.py -l memtest.log -w -u"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    initial_group = parser.add_mutually_exclusive_group()
    initial_group.add_argument(
        "-f",
        "--file-initial",
        type=Path,
        help="Optional text file containing PFNs already known to be bad.",
    )
    initial_group.add_argument(
        "-w",
        "--windows-initial",
        action="store_true",
        help=(
            "Read the initial bad-memory list from the current Windows "
            "``{badmemory}`` store when running on Windows. "
            "Mutually exclusive with --file-initial."
        ),
    )

    parser.add_argument(
        "-m",
        "--memtest-log",
        required=True,
        type=Path,
        help="Path to the MemTest86 log file to analyze.",
    )
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        default="./",
        help=("Directory where output files will be created (default: %(default)s)."),
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Remove existing selected output files before creating them.",
    )
    parser.add_argument(
        "-r",
        "--report",
        action="store_true",
        help="Generate the detailed report in badmemory_reports.json.",
    )
    parser.add_argument(
        "-b",
        "--write-list",
        action="store_true",
        help="Write the final PFN list to badmemorylist.txt.",
    )

    update_group = parser.add_mutually_exclusive_group()
    update_group.add_argument(
        "-s",
        "--script",
        action="store_true",
        help="Generate a Windows batch script in badmemorylist.bat.",
    )
    update_group.add_argument(
        "-u",
        "--update-windows",
        action="store_true",
        help=(
            "Update the Windows {badmemory} store directly (requires "
            "administrator privileges); mutually exclusive with --script."
        ),
    )

    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Print additional logs, statistics and a status map.",
    )

    parsed_args = parser.parse_args(args)

    if not (parsed_args.write_list or parsed_args.script or parsed_args.update_windows):
        parser.error(
            "at least one of --write-list, --script, or --update-windows is required"
        )

    return parsed_args


def main(args: list[str] | None = None):
    """Run the complete MemTest86 analysis workflow.

    The function parses CLI options, merges the known bad-PFN list with the log
    findings, displays the summary, and performs the selected output action.

    Args:
        args (list[str] | None): Optional command-line arguments passed to
            ``parse_args``.

    Raises:
        SystemExit: If command-line arguments are invalid.
        FileNotFoundError: If an input file does not exist.
        FileExistsError: If an output file already exists and ``--force`` is not set.
        OSError: If a Windows bad-memory list update fails or is requested
            outside Windows.
        ValueError: If a script or a Windows update is requested when
            no PFNs were found.

    Returns:
        None
    """
    args = parse_args(args)

    pfns_initial = None
    if args.windows_initial:
        pfns_initial = read_pfns_from_windows()
    elif args.file_initial:
        pfns_initial = read_pfns_from_file(args.file_initial)

    page_states = build_pfn_states(args.memtest_log, pfns_initial)
    pfns = sorted(page_states.keys())

    if args.verbose:
        stats = calculate_stats(page_states)
        status_range = build_pfn_status_range(page_states)

        display_stats(stats)

        allow_colors = (
            sys.stdout.isatty()
            and "NO_COLOR" not in os.environ
            and os.environ.get("TERM") != "dumb"
        )

        display_pfn_status_range(status_range, use_colors=allow_colors)

    if args.report or args.write_list or args.script:
        output_dir = Path(args.output)
        output_dir.mkdir(parents=True, exist_ok=True)

    if args.report:
        write_report(page_states, output_dir / "badmemory_reports.json", args.force)

    if args.write_list:
        write_badmemory_list(pfns, output_dir / "badmemorylist.txt", args.force)

    if args.update_windows or args.script:
        if not pfns:
            raise ValueError("No PFNs to put in a bad-memory command.")
        cmd = build_bcdedit_command(pfns)

    if args.update_windows:
        launch_windows_command(cmd)
    elif args.script:
        write_bcdedit_script(cmd, output_dir / "badmemorylist.bat", args.force)


if __name__ == "__main__":
    main()
