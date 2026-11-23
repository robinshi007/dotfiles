"""Plan/verify step results, table output and ``--json`` serialisation."""

import json
from collections.abc import Sequence
from dataclasses import asdict, dataclass
from enum import StrEnum


class Status(StrEnum):
    OK = "OK"
    SKIPPED = "SKIPPED"
    CHANGED = "CHANGED"
    FAIL = "FAIL"
    PLANNED = "PLANNED"


@dataclass(frozen=True)
class StepResult:
    name: str
    status: Status
    detail: str = ""


def render_table(headers: Sequence[str], rows: Sequence[Sequence[str]]) -> str:
    columns = len(headers)
    widths = [len(h) for h in headers]
    for row in rows:
        for index in range(columns):
            widths[index] = max(widths[index], len(str(row[index])))
    lines = [
        "  ".join(str(h).ljust(widths[i]) for i, h in enumerate(headers)).rstrip(),
        "  ".join("-" * widths[i] for i in range(columns)),
    ]
    for row in rows:
        lines.append(
            "  ".join(str(row[i]).ljust(widths[i]) for i in range(columns)).rstrip()
        )
    return "\n".join(lines)


def print_table(
    headers: Sequence[str],
    rows: Sequence[Sequence[str]],
    *,
    as_json: bool = False,
    payload: object | None = None,
) -> None:
    if as_json:
        print(json.dumps(payload if payload is not None else rows, indent=2, default=str))
        return
    if rows:
        print(render_table(headers, rows))
    else:
        print("(no data)")


def print_steps(steps: Sequence[StepResult], *, as_json: bool = False) -> None:
    if as_json:
        print(json.dumps([asdict(step) for step in steps], indent=2))
        return
    for step in steps:
        line = f"{step.status.value:<8} {step.name}"
        if step.detail:
            line += f": {step.detail}"
        print(line)


def print_json(payload: object) -> None:
    print(json.dumps(payload, indent=2, default=str))
