"""Plan/verify step results, table output and ``--json`` serialisation."""

import json
from collections.abc import Sequence
from dataclasses import asdict, dataclass
from enum import StrEnum

from lhm.core import colors
from lhm.core.colors import Color

# A row color is either one color for the whole row or one color per cell.
RowColor = Color | Sequence[Color | None] | None


class Status(StrEnum):
    OK = "OK"
    SKIPPED = "SKIPPED"
    CHANGED = "CHANGED"
    FAIL = "FAIL"
    PLANNED = "PLANNED"
    # The user (or a non-TTY stdin) refused the confirmation: nothing was
    # changed, which is not the same outcome as "already done" or "failed".
    ABORTED = "ABORTED"


@dataclass(frozen=True)
class StepResult:
    name: str
    status: Status
    detail: str = ""


def _cell_color(row_color: RowColor, index: int) -> Color | None:
    if row_color is None or isinstance(row_color, Color):
        return row_color
    return row_color[index] if index < len(row_color) else None


def render_table(
    headers: Sequence[str],
    rows: Sequence[Sequence[str]],
    row_colors: Sequence[RowColor] | None = None,
) -> str:
    columns = len(headers)
    widths = [len(h) for h in headers]
    for row in rows:
        for index in range(columns):
            widths[index] = max(widths[index], len(str(row[index])))
    lines = [
        "  ".join(str(h).ljust(widths[i]) for i, h in enumerate(headers)).rstrip(),
        "  ".join("-" * widths[i] for i in range(columns)),
    ]
    for row_index, row in enumerate(rows):
        row_color = (
            row_colors[row_index]
            if row_colors is not None and row_index < len(row_colors)
            else None
        )
        if row_color is None:
            lines.append(
                "  ".join(str(row[i]).ljust(widths[i]) for i in range(columns)).rstrip()
            )
            continue
        # The last cell is printed unpadded; the others keep their width so the
        # (invisible) padding inside an escape sequence cannot break alignment.
        cells = []
        for index in range(columns):
            text = str(row[index])
            if index < columns - 1:
                text = text.ljust(widths[index])
            cells.append(colors.paint(text, _cell_color(row_color, index)))
        lines.append("  ".join(cells))
    return "\n".join(lines)


def print_table(
    headers: Sequence[str],
    rows: Sequence[Sequence[str]],
    *,
    as_json: bool = False,
    payload: object | None = None,
    row_colors: Sequence[RowColor] | None = None,
) -> None:
    if as_json:
        print(json.dumps(payload if payload is not None else rows, indent=2, default=str))
        return
    if rows:
        print(render_table(headers, rows, row_colors))
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
