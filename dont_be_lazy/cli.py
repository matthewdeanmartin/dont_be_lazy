"""Command-line entry point for dont_be_lazy."""

from __future__ import annotations

import argparse
import collections
import contextlib
import fnmatch
import json
import os
import re
import subprocess  # nosec B404
import sys

from dont_be_lazy.__about__ import __version__
from dont_be_lazy.commands.baseline_cmd import (
    baseline_first_seen_map,
    check_new_findings,
    create_baseline,
    format_check_result,
    load_baseline,
    prune_baseline,
    save_baseline,
)
from dont_be_lazy.commands.explain_cmd import (
    explain_suppression,
    explain_suppression_json,
    find_suppression_by_id,
    find_suppression_by_location,
)
from dont_be_lazy.commands.owners_cmd import attach_owners, format_owners_json, format_owners_table, load_owner_map
from dont_be_lazy.commands.rules_cmd import format_rules_list, format_rules_test
from dont_be_lazy.commands.stale_cmd import (
    age_in_days,
    attach_blame,
    filter_stale,
    format_stale_json,
    format_stale_table,
    parse_age,
)
from dont_be_lazy.config_loader import discover_config
from dont_be_lazy.diff import build_diff_index, files_changed_since, suppression_in_diff
from dont_be_lazy.formatters.json_fmt import format_json, format_jsonl
from dont_be_lazy.formatters.markdown_fmt import format_markdown
from dont_be_lazy.formatters.sarif import format_sarif
from dont_be_lazy.formatters.table import format_table
from dont_be_lazy.git import GIT_BIN
from dont_be_lazy.models import RiskLevel, Suppression
from dont_be_lazy.parallel import parallel_scan_configs, parallel_scan_py
from dont_be_lazy.policy import check_all
from dont_be_lazy.registry import all_tools, config_entries, entries_for_tool, inline_entries
from dont_be_lazy.risk import discount
from dont_be_lazy.scanners.config import find_and_scan_configs
from dont_be_lazy.walker import walk_paths


def _find_root(explicit: str | None) -> str:
    """Return the repository root derived from --root, Git, or the cwd."""
    if explicit:
        return os.path.abspath(explicit)
    try:
        result = subprocess.run(  # nosec B603
            [GIT_BIN, "rev-parse", "--show-toplevel"],
            capture_output=True,
            check=False,
            text=True,
            timeout=5,
        )
        if result.returncode == 0:
            return result.stdout.strip()
    except (OSError, subprocess.SubprocessError):
        pass
    return os.getcwd()


def _build_global_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="dont_be_lazy",
        description="Find the ignores you forgot to come back to.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument("--root", metavar="PATH", help="Repo root (default: git root or cwd)")
    parser.add_argument("--config", metavar="PATH", help="Config file path")
    parser.add_argument("--include", metavar="GLOB", action="append", default=[], dest="include")
    parser.add_argument("--exclude", metavar="GLOB", action="append", default=[], dest="exclude")
    parser.add_argument("--respect-gitignore", action="store_true", default=True, dest="respect_gitignore")
    parser.add_argument("--no-respect-gitignore", action="store_false", dest="respect_gitignore")
    parser.add_argument("--follow-symlinks", action="store_true", default=False)
    parser.add_argument("--jobs", type=int, default=None, metavar="N")
    parser.add_argument("--encoding", default="utf-8")
    parser.add_argument("--stdin", action="store_true", default=False)
    parser.add_argument("--no-color", action="store_true", default=False)
    parser.add_argument("-v", "--verbose", action="store_true", default=False)
    parser.add_argument("-q", "--quiet", action="store_true", default=False)
    return parser


def _add_scan_subparser(sub: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    p = sub.add_parser("scan", help="Scan for suppressions")
    p.add_argument("paths", nargs="*", metavar="PATH", help="Paths to scan (default: root)")
    p.add_argument("--format", choices=["table", "json", "jsonl", "markdown", "sarif"], default="table", dest="format_")
    p.add_argument("--output", metavar="PATH", help="Write output to file")
    p.add_argument("--tool", action="append", default=[], dest="tools")
    p.add_argument("--kind", action="append", default=[], dest="kinds")
    p.add_argument("--scope", action="append", default=[], dest="scopes")
    p.add_argument("--risk", choices=["low", "medium", "high", "critical"], default=None)
    p.add_argument("--fail-on", choices=["low", "medium", "high", "critical"], default=None, dest="fail_on")
    p.add_argument("--fail-on-count", type=int, default=None, dest="fail_on_count")
    p.add_argument("--fail-on-stale", default=None, metavar="AGE", dest="fail_on_stale")
    p.add_argument("--require-reason", action="store_true", default=False, dest="require_reason")
    p.add_argument("--min-age", default=None, metavar="AGE", dest="min_age")
    p.add_argument("--no-config-suppressions", action="store_true", default=False, dest="no_config_suppressions")
    p.add_argument("--no-test-suppressions", action="store_true", default=False, dest="no_test_suppressions")
    p.add_argument("--show-context", type=int, default=0, metavar="N", dest="show_context")
    p.add_argument("--no-respect-gitignore", action="store_false", dest="respect_gitignore", default=True)
    # Phase 3 options
    p.add_argument("--since", default=None, metavar="REF", help="Scan only files changed since git REF")
    p.add_argument("--baseline", default=None, metavar="PATH", help="Baseline file for new-only mode")
    p.add_argument("--update-baseline", default=None, metavar="PATH", dest="update_baseline")
    p.add_argument("--new-only", action="store_true", default=False, dest="new_only")
    p.add_argument("--with-git-blame", action="store_true", default=False, dest="with_git_blame")
    p.add_argument("--with-git-history", action="store_true", default=False, dest="with_git_history")
    p.set_defaults(command="scan")


def _add_summary_subparser(sub: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    p = sub.add_parser("summary", help="High-level summary counts")
    p.add_argument("paths", nargs="*", metavar="PATH")
    p.add_argument("--by", choices=["tool", "kind", "scope", "path", "owner", "age", "risk"], default="tool")
    p.add_argument("--format", choices=["table", "json", "markdown"], default="table", dest="format_")
    p.add_argument("--with-git-blame", action="store_true", default=False, dest="with_git_blame")
    p.add_argument("--top", type=int, default=None, metavar="N")
    p.add_argument("--no-respect-gitignore", action="store_false", dest="respect_gitignore", default=True)
    p.set_defaults(command="summary")


def _add_list_subparser(sub: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    p = sub.add_parser("list", help="List known suppression patterns")
    p.add_argument("what", choices=["tools", "checks", "patterns"])
    p.add_argument("--tool", default=None)
    p.add_argument("--format", choices=["table", "json", "markdown"], default="table", dest="format_")
    p.add_argument("--only-inline", action="store_true", default=False)
    p.add_argument("--only-config", action="store_true", default=False)
    p.set_defaults(command="list")


def _add_config_suppressions_subparser(sub: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    p = sub.add_parser("config-suppressions", help="Scan config-file-level suppressions")
    p.add_argument("--tool", default=None)
    p.add_argument("--format", choices=["table", "json", "markdown"], default="table", dest="format_")
    p.add_argument("--explain", action="store_true", default=False)
    p.set_defaults(command="config-suppressions")


def _add_stale_subparser(sub: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    p = sub.add_parser("stale", help="Find old/stale suppressions")
    p.add_argument("paths", nargs="*", metavar="PATH")
    p.add_argument(
        "--older-than",
        default="180d",
        dest="older_than",
        metavar="AGE",
        help="Age threshold (e.g. 180d, 6m, 1y). Default: 180d",
    )
    p.add_argument("--with-git-blame", action="store_true", default=False, dest="with_git_blame")
    p.add_argument("--with-git-history", action="store_true", default=False, dest="with_git_history")
    p.add_argument("--baseline", default=None, metavar="PATH")
    p.add_argument("--format", choices=["table", "json", "markdown"], default="table", dest="format_")
    p.add_argument("--group-by", choices=["tool", "path", "risk", "owner"], default="tool", dest="group_by")
    p.add_argument("--no-respect-gitignore", action="store_false", dest="respect_gitignore", default=True)
    p.set_defaults(command="stale")


def _add_owners_subparser(sub: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    p = sub.add_parser("owners", help="Group suppressions by git blame author")
    p.add_argument("paths", nargs="*", metavar="PATH")
    p.add_argument("--owner-map", default=None, metavar="PATH", dest="owner_map")
    p.add_argument("--group-by", choices=["author", "email", "team", "path"], default="author", dest="group_by")
    p.add_argument("--format", choices=["table", "json", "markdown"], default="table", dest="format_")
    p.add_argument("--no-respect-gitignore", action="store_false", dest="respect_gitignore", default=True)
    p.set_defaults(command="owners")


def _add_explain_subparser(sub: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    p = sub.add_parser("explain", help="Explain a suppression by location or ID")
    p.add_argument("target", metavar="PATH:LINE or DBL...", help="Location as path:line or a DBL... suppression ID")
    p.add_argument("--format", choices=["text", "json"], default="text", dest="format_")
    p.set_defaults(command="explain")


def _add_baseline_subparser(sub: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    p = sub.add_parser("baseline", help="Manage suppression baseline")
    bsub = p.add_subparsers(dest="baseline_command")

    create = bsub.add_parser("create", help="Create a new baseline")
    create.add_argument("paths", nargs="*", metavar="PATH")
    create.add_argument("--output", default=".dont-be-lazy-baseline.json", metavar="PATH")
    create.add_argument("--no-respect-gitignore", action="store_false", dest="respect_gitignore", default=True)

    check = bsub.add_parser("check", help="Check findings against a baseline")
    check.add_argument("paths", nargs="*", metavar="PATH")
    check.add_argument("--baseline", default=".dont-be-lazy-baseline.json", metavar="PATH")
    check.add_argument("--format", choices=["table", "json"], default="table", dest="format_")
    check.add_argument("--no-respect-gitignore", action="store_false", dest="respect_gitignore", default=True)

    prune = bsub.add_parser("prune", help="Remove resolved suppressions from baseline")
    prune.add_argument("paths", nargs="*", metavar="PATH")
    prune.add_argument("--baseline", default=".dont-be-lazy-baseline.json", metavar="PATH")
    prune.add_argument("--output", default=None, metavar="PATH", help="Write pruned baseline here (default: overwrite)")
    prune.add_argument("--no-respect-gitignore", action="store_false", dest="respect_gitignore", default=True)

    p.set_defaults(command="baseline")


def _add_rules_subparser(sub: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    p = sub.add_parser("rules", help="List and test policy rules")
    rsub = p.add_subparsers(dest="rules_command")

    lst = rsub.add_parser("list", help="List active policy rules")
    lst.add_argument("--format", choices=["table", "json", "markdown"], default="table", dest="format_")

    tst = rsub.add_parser("test", help="Run policy rules against current findings")
    tst.add_argument("paths", nargs="*", metavar="PATH")
    tst.add_argument("--format", choices=["table", "json"], default="table", dest="format_")
    tst.add_argument("--no-respect-gitignore", action="store_false", dest="respect_gitignore", default=True)

    p.set_defaults(command="rules")


# ---------------------------------------------------------------------------
# Shared scan helper
# ---------------------------------------------------------------------------


def _collect_findings(
    args: argparse.Namespace,
    root: str,
    scan_paths: list[str] | None = None,
    no_config: bool = False,
    no_tests: bool = False,
) -> list[Suppression]:
    cfg = discover_config(root, getattr(args, "config", None))
    jobs = getattr(args, "jobs", None)

    findings: list[Suppression] = []
    if scan_paths is None:
        paths_arg = getattr(args, "paths", []) or []
        scan_paths = [os.path.abspath(p) for p in paths_arg] if paths_arg else [root]

    if getattr(args, "stdin", False):
        stdin_paths = [line.rstrip("\n") for line in sys.stdin if line.strip()]
        scan_paths = [os.path.abspath(p) for p in stdin_paths]

    respect_gi = getattr(args, "respect_gitignore", True)
    encoding = getattr(args, "encoding", "utf-8")

    py_extensions = {".py", ".pyi"}
    config_extensions = {".toml", ".ini", ".cfg", ".yaml", ".yml", ".json"}

    py_paths = []
    cfg_paths = []

    for scan_root in scan_paths:
        if os.path.isfile(scan_root):
            file_paths = [scan_root]
        else:
            file_paths = list(
                walk_paths(
                    scan_root,
                    include_globs=getattr(args, "include", None) or None,
                    exclude_globs=getattr(args, "exclude", None) or None,
                    respect_gitignore=respect_gi,
                )
            )
        for path in file_paths:
            _, ext = os.path.splitext(path)
            if ext in py_extensions:
                py_paths.append(path)
            elif ext in config_extensions and not no_config:
                cfg_paths.append(path)

    # Parallel Python scan
    findings.extend(
        parallel_scan_py(
            py_paths,
            encoding=encoding,
            scan_comments=True,
            scan_ast=not no_tests,
            custom_patterns_cfg=cfg.get("custom_patterns", {}),
            jobs=jobs,
        )
    )

    # Parallel config scan
    if not no_config:
        findings.extend(parallel_scan_configs(cfg_paths, jobs=jobs))
        findings.extend(find_and_scan_configs(root))

    # Deduplicate by id
    seen: set[str] = set()
    unique: list[Suppression] = []
    for s in findings:
        if s.id not in seen:
            seen.add(s.id)
            unique.append(s)
    _apply_generated_risk_discount(unique, root, cfg)
    return unique


def _apply_generated_risk_discount(findings: list[Suppression], root: str, cfg: dict[str, object]) -> None:
    generated_cfg = cfg.get("generated", {})
    if not isinstance(generated_cfg, dict) or not generated_cfg.get("risk_discount"):
        return
    raw_paths = generated_cfg.get("paths", [])
    if not isinstance(raw_paths, list):
        return

    patterns = [str(pattern) for pattern in raw_paths]
    for finding in findings:
        rel_path = os.path.relpath(finding.path, root) if os.path.isabs(finding.path) else finding.path
        if any(fnmatch.fnmatch(rel_path, pattern) for pattern in patterns):
            finding.risk = discount(finding.risk)
            if "generated-path" not in finding.flags:
                finding.flags.append("generated-path")


def _attach_context(findings: list[Suppression], lines_of_context: int) -> None:
    if lines_of_context <= 0:
        return

    by_path: dict[str, list[Suppression]] = {}
    for finding in findings:
        if finding.line <= 0:
            continue
        by_path.setdefault(finding.path, []).append(finding)

    for path, path_findings in by_path.items():
        try:
            with open(path, encoding="utf-8", errors="replace") as handle:
                source_lines = handle.read().splitlines()
        except OSError:
            continue
        for finding in path_findings:
            start = max(1, finding.line - lines_of_context)
            end = min(len(source_lines), finding.line + lines_of_context)
            finding.context = [
                f"{line_number}: {source_lines[line_number - 1]}" for line_number in range(start, end + 1)
            ]


def _filter_findings_to_changed_lines(
    findings: list[Suppression],
    diff_index: dict[str, list[tuple[int, int]]],
) -> list[Suppression]:
    filtered: list[Suppression] = []
    for finding in findings:
        hunks = diff_index.get(finding.path)
        if hunks is None:
            continue
        if finding.line <= 0 or suppression_in_diff(finding.line, hunks):
            filtered.append(finding)
    return filtered


def _age_bucket(first_seen: str | None) -> str:
    if not first_seen:
        return "unknown"
    days = age_in_days(first_seen)
    if days < 30:
        return "<30d"
    if days < 180:
        return "30-179d"
    if days < 365:
        return "180-364d"
    return "365+d"


# ---------------------------------------------------------------------------
# Command implementations
# ---------------------------------------------------------------------------


def _run_scan(args: argparse.Namespace, root: str) -> int:
    since_ref = getattr(args, "since", None)
    scan_paths: list[str] | None = None

    if since_ref:
        changed = files_changed_since(since_ref, root)
        if not changed:
            if not args.quiet:
                print(f"No files changed since {since_ref}")
            return 0
        scan_paths = list(changed)

    findings = _collect_findings(
        args,
        root,
        scan_paths=scan_paths,
        no_config=args.no_config_suppressions,
        no_tests=args.no_test_suppressions,
    )
    if since_ref and scan_paths:
        diff_index = build_diff_index(since_ref, scan_paths, root)
        findings = _filter_findings_to_changed_lines(findings, diff_index)

    # Baseline: new-only
    baseline_data: dict[str, object] | None = None
    if args.baseline:
        try:
            baseline_data = load_baseline(args.baseline)
        except OSError:
            print(f"Warning: baseline not found: {args.baseline}", file=sys.stderr)

    if baseline_data and args.new_only:
        new_findings, _ = check_new_findings(findings, baseline_data)
        findings = new_findings

    first_seen_map = baseline_first_seen_map(baseline_data) if baseline_data else None
    age_required = bool(args.min_age or args.fail_on_stale or args.with_git_blame or args.with_git_history)
    if age_required:
        findings = attach_blame(
            findings,
            root,
            baseline=first_seen_map,
            with_git_blame=args.with_git_blame,
            with_git_history=args.with_git_history,
        )

    # Update baseline
    if args.update_baseline:
        bl = create_baseline(findings)
        save_baseline(bl, args.update_baseline)
        if not args.quiet:
            print(f"Baseline written to {args.update_baseline} ({len(findings)} entries)")

    # Filter
    if args.tools:
        findings = [s for s in findings if s.tool in args.tools]
    if args.kinds:
        findings = [s for s in findings if s.kind in args.kinds]
    if args.scopes:
        findings = [s for s in findings if s.scope.value in args.scopes]
    if args.risk:
        min_risk = RiskLevel(args.risk)
        findings = [s for s in findings if s.risk >= min_risk]
    if args.require_reason:
        findings = [s for s in findings if not s.reason]
    if args.min_age:
        min_age_days = parse_age(args.min_age)
        findings = filter_stale(findings, min_age_days, include_unknown=False)

    _attach_context(findings, getattr(args, "show_context", 0))

    # Sort by risk desc, then path, line
    _order = [RiskLevel.critical, RiskLevel.high, RiskLevel.medium, RiskLevel.low]
    findings.sort(key=lambda s: (_order.index(s.risk), s.path, s.line))

    no_color = getattr(args, "no_color", False)
    output = _format_findings(findings, args.format_, root, no_color=no_color)

    if getattr(args, "output", None):
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(output)
    else:
        if not args.quiet:
            print(output, end="")

    # Exit code logic
    if args.fail_on:
        fail_level = RiskLevel(args.fail_on)
        if any(s.risk >= fail_level for s in findings):
            return 1
    if args.fail_on_count is not None and len(findings) > args.fail_on_count:
        return 1
    if args.fail_on_stale:
        stale_findings = filter_stale(findings, parse_age(args.fail_on_stale), include_unknown=False)
        if stale_findings:
            return 1

    return 0


def _run_summary(args: argparse.Namespace, root: str) -> int:
    findings = _collect_findings(args, root)
    if args.by == "owner" or args.with_git_blame:
        findings = attach_owners(findings, root)
    if args.by == "age":
        findings = attach_blame(findings, root, with_git_blame=args.with_git_blame)

    if not args.quiet:
        _print_summary(findings, args.by, args.format_, getattr(args, "top", None))
    return 0


def _print_summary(findings: list[Suppression], by: str, fmt: str, top: int | None = None) -> None:
    """Print grouped summary counts for the current findings."""
    groups: dict[str, list[Suppression]] = collections.defaultdict(list)
    for s in findings:
        if by == "risk":
            key = s.risk.value
        elif by == "owner":
            key = s.owner or s.git_author or "unknown"
        elif by == "age":
            key = _age_bucket(s.first_seen)
        else:
            key = getattr(s, by, s.tool)
        groups[str(key)].append(s)

    if fmt == "json":
        doc = {k: len(v) for k, v in sorted(groups.items())}
        print(json.dumps({"total": len(findings), by: doc}, indent=2))
        return

    header = f"{'Group':<30} {'Count':>6}  {'High+':>6}  {'No reason':>9}"
    print("Suppression summary")
    print()
    print(header)
    print("-" * len(header))
    ordered_keys = sorted(groups, key=lambda k: -len(groups[k]))
    if top is not None:
        ordered_keys = ordered_keys[:top]
    for group_key in ordered_keys:
        sups = groups[group_key]
        high = sum(1 for s in sups if s.risk in (RiskLevel.high, RiskLevel.critical))
        no_reason = sum(1 for s in sups if not s.reason)
        print(f"{group_key:<30} {len(sups):>6}  {high:>6}  {no_reason:>9}")
    print()
    print(f"Total: {len(findings)} suppressions")


def _run_list(args: argparse.Namespace) -> int:
    tool_filter = getattr(args, "tool", None)
    only_inline = getattr(args, "only_inline", False)
    only_config = getattr(args, "only_config", False)
    what = args.what

    if what == "tools":
        tools = all_tools() if not tool_filter else ([tool_filter] if tool_filter in all_tools() else [])
        print("\n".join(tools))

    elif what in ("checks", "patterns"):
        if only_inline:
            entries = inline_entries(tool_filter)
        elif only_config:
            entries = config_entries(tool_filter)
        else:
            entries = entries_for_tool(tool_filter)

        if args.format_ == "json":
            print(
                json.dumps(
                    [
                        {
                            "tool": e.tool,
                            "kind": e.kind,
                            "example": e.example,
                            "scope": e.scope,
                            "inline": e.inline,
                            "risk_default": e.risk_default,
                            "description": e.description,
                        }
                        for e in entries
                    ],
                    indent=2,
                )
            )
        elif args.format_ == "markdown":
            print("| Tool | Kind | Example | Scope | Risk |")
            print("|---|---|---|---|---|")
            for e in entries:
                print(f"| {e.tool} | {e.kind} | `{e.example}` | {e.scope} | {e.risk_default} |")
        else:
            for e in entries:
                print(f"{e.tool:<14}  {e.kind:<30}  {e.example}")
    return 0


def _run_config_suppressions(args: argparse.Namespace, root: str) -> int:
    findings = find_and_scan_configs(root)
    if getattr(args, "tool", None):
        findings = [s for s in findings if s.tool == args.tool]

    output = _format_findings(findings, args.format_, root, no_color=getattr(args, "no_color", False))
    if not args.quiet:
        print(output, end="")
    return 0


def _run_stale(args: argparse.Namespace, root: str) -> int:
    findings = _collect_findings(args, root)

    baseline_data = None
    if getattr(args, "baseline", None):
        with contextlib.suppress(OSError):
            baseline_data = load_baseline(args.baseline)

    first_seen_map = baseline_first_seen_map(baseline_data) if baseline_data else None

    older_than = parse_age(getattr(args, "older_than", "180d"))
    findings = attach_blame(
        findings,
        root,
        baseline=first_seen_map,
        with_git_blame=getattr(args, "with_git_blame", False),
        with_git_history=getattr(args, "with_git_history", False),
    )
    stale = filter_stale(findings, older_than)

    fmt = getattr(args, "format_", "table")
    group_by = getattr(args, "group_by", "tool")

    output = format_stale_json(stale) if fmt == "json" else format_stale_table(stale, group_by=group_by)

    if not args.quiet:
        print(output, end="")

    return 1 if stale else 0


def _run_owners(args: argparse.Namespace, root: str) -> int:
    findings = _collect_findings(args, root)

    owner_map = None
    if getattr(args, "owner_map", None):
        owner_map = load_owner_map(args.owner_map)

    findings = attach_owners(findings, root, owner_map=owner_map)

    fmt = getattr(args, "format_", "table")
    if fmt == "json":
        output = format_owners_json(findings)
    else:
        output = format_owners_table(findings, group_by=getattr(args, "group_by", "author"))

    if not args.quiet:
        print(output, end="")
    return 0


def _run_explain(args: argparse.Namespace, root: str) -> int:
    target = args.target

    findings = _collect_findings(args, root)

    suppression = None
    if re.match(r"^DBL[0-9A-F]{8}$", target, re.IGNORECASE):
        suppression = find_suppression_by_id(findings, target)
    else:
        # path:line
        m = re.match(r"^(.+):(\d+)$", target)
        if m:
            path, line = m.group(1), int(m.group(2))
            suppression = find_suppression_by_location(findings, path, line)

    if suppression is None:
        print(f"No suppression found for: {target}", file=sys.stderr)
        return 1

    fmt = getattr(args, "format_", "text")
    if fmt == "json":
        print(json.dumps(explain_suppression_json(suppression), indent=2))
    else:
        print(explain_suppression(suppression), end="")
    return 0


def _run_baseline(args: argparse.Namespace, root: str) -> int:
    subcmd = getattr(args, "baseline_command", None)
    exit_code = 2
    if subcmd is None:
        print("Usage: dont_be_lazy baseline {create,check,prune}", file=sys.stderr)
    else:
        findings = _collect_findings(args, root)

        if subcmd == "create":
            bl = create_baseline(findings)
            output_path = getattr(args, "output", ".dont-be-lazy-baseline.json")
            save_baseline(bl, output_path)
            if not args.quiet:
                print(f"Baseline created: {output_path} ({len(findings)} entries)")
            exit_code = 0
        elif subcmd in {"check", "prune"}:
            baseline_path = getattr(args, "baseline", ".dont-be-lazy-baseline.json")
            try:
                baseline_data = load_baseline(baseline_path)
            except OSError as e:
                print(f"Cannot read baseline: {e}", file=sys.stderr)
            else:
                if subcmd == "check":
                    new, known = check_new_findings(findings, baseline_data)
                    fmt = getattr(args, "format_", "table")
                    output = format_check_result(new, len(known), fmt)
                    if not args.quiet:
                        print(output, end="")
                    exit_code = 1 if new else 0
                else:
                    pruned, removed = prune_baseline(baseline_data, findings)
                    output_path = getattr(args, "output", None) or baseline_path
                    save_baseline(pruned, output_path)
                    if not args.quiet:
                        print(
                            f"Pruned {len(removed)} resolved entries; "
                            f"{len(pruned['entries'])} remain → {output_path}"
                        )
                    exit_code = 0

    return exit_code


def _run_rules(args: argparse.Namespace, root: str) -> int:
    subcmd = getattr(args, "rules_command", None)
    fmt = getattr(args, "format_", "table")

    if subcmd == "list" or subcmd is None:
        print(format_rules_list(fmt), end="")
        return 0

    if subcmd == "test":
        cfg = discover_config(root, getattr(args, "config", None))
        policy = cfg.get("policy", {})
        findings = _collect_findings(args, root)
        violations = check_all(findings, policy)
        print(format_rules_test(violations, fmt), end="")
        return 1 if violations else 0

    return 2


def _format_findings(findings: list[Suppression], fmt: str, root: str, no_color: bool = False) -> str:
    """Dispatch findings to the requested output formatter."""
    if fmt == "json":
        return format_json(findings, root)
    if fmt == "jsonl":
        return format_jsonl(findings)
    if fmt == "markdown":
        return format_markdown(findings, root)
    if fmt == "sarif":
        return format_sarif(findings, root)
    return format_table(findings, no_color=no_color)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main() -> None:
    """Parse CLI arguments and dispatch to the selected subcommand."""
    parser = _build_global_parser()
    sub = parser.add_subparsers(dest="command")
    _add_scan_subparser(sub)
    _add_summary_subparser(sub)
    _add_list_subparser(sub)
    _add_config_suppressions_subparser(sub)
    _add_stale_subparser(sub)
    _add_owners_subparser(sub)
    _add_explain_subparser(sub)
    _add_baseline_subparser(sub)
    _add_rules_subparser(sub)

    args = parser.parse_args()
    # Apply global defaults to any attrs that subcommands may not define
    if not hasattr(args, "quiet"):
        args.quiet = False
    if not hasattr(args, "verbose"):
        args.verbose = False
    if not hasattr(args, "encoding"):
        args.encoding = "utf-8"
    if not hasattr(args, "respect_gitignore"):
        args.respect_gitignore = True
    if not hasattr(args, "no_color"):
        args.no_color = False
    root = _find_root(getattr(args, "root", None))

    if not hasattr(args, "command") or args.command is None:
        parser.print_help()
        sys.exit(0)

    try:
        if args.command == "scan":
            sys.exit(_run_scan(args, root))
        if args.command == "summary":
            sys.exit(_run_summary(args, root))
        if args.command == "list":
            sys.exit(_run_list(args))
        if args.command == "config-suppressions":
            sys.exit(_run_config_suppressions(args, root))
        if args.command == "stale":
            sys.exit(_run_stale(args, root))
        if args.command == "owners":
            sys.exit(_run_owners(args, root))
        if args.command == "explain":
            sys.exit(_run_explain(args, root))
        if args.command == "baseline":
            sys.exit(_run_baseline(args, root))
        if args.command == "rules":
            sys.exit(_run_rules(args, root))
        parser.print_help()
        sys.exit(2)
    except KeyboardInterrupt:
        sys.exit(0)
    except Exception as exc:  # pylint: disable=broad-exception-caught
        print(f"Internal error: {exc}", file=sys.stderr)
        sys.exit(4)


if __name__ == "__main__":
    main()
