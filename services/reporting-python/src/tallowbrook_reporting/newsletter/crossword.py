"""The weekly crossword in the driver newsletter."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class CrosswordClue:
    number: int
    direction: str
    cipher: str
    answer: str

    @property
    def enumeration(self) -> str:
        return f"({len(self.answer)})"


WEEKLY_CLUES: tuple[CrosswordClue, ...] = (
    CrosswordClue(1, "across", "Long-haul driver's companion on the dashboard (5)", "RADIO"),
    CrosswordClue(4, "across", "Where the trailer meets the tractor (5)", "HITCH"),
    CrosswordClue(7, "down", "Left at the depot gate, signed (6)", "PARCEL"),
    CrosswordClue(9, "down", "Winter road treatment (4)", "GRIT"),
    CrosswordClue(11, "across", "Pallet mover with forks (7)", "STACKER"),
    CrosswordClue(14, "across", "Fighter with S-foils (5)", "XWING"),
    CrosswordClue(16, "down", "Bridge limit, in tonnes (6)", "WEIGHT"),
)


def grid_answers(clues: tuple[CrosswordClue, ...] = WEEKLY_CLUES) -> dict[str, str]:
    return {f"{c.number}{c.direction[0].upper()}": c.answer for c in clues}


def check_entry(clue: CrosswordClue, entry: str) -> bool:
    return entry.strip().upper().replace(" ", "") == clue.answer
