"""Driver training records: course completions and when they lapse."""

from __future__ import annotations

import calendar
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import date, timedelta


@dataclass(frozen=True)
class Course:
    code: str
    title: str
    valid_months: int
    mandatory: bool = True


COURSES = {
    "ADR-BASIC": Course("ADR-BASIC", "Dangerous goods by road, basic", valid_months=60),
    "FORKLIFT": Course("FORKLIFT", "Counterbalance forklift", valid_months=36),
    "COLD-CHAIN": Course(
        "COLD-CHAIN", "Temperature-controlled loads", valid_months=24, mandatory=False
    ),
    "DEFENSIVE": Course("DEFENSIVE", "Defensive driving refresher", valid_months=12),
}


@dataclass(frozen=True)
class TrainingCertificate:
    driver_id: str
    course_code: str
    issued_on: date
    expires_on: date

    def lapses_within(self, days: int, today: date) -> bool:
        return today <= self.expires_on <= today + timedelta(days=days)


def _add_months(start: date, months: int) -> date:
    month = start.month - 1 + months
    year = start.year + month // 12
    month = month % 12 + 1
    return date(year, month, min(start.day, calendar.monthrange(year, month)[1]))


def issue_certificate(driver_id: str, course: Course) -> TrainingCertificate:
    issued = date.today()
    return TrainingCertificate(
        driver_id, course.code, issued, _add_months(issued, course.valid_months)
    )


def due_for_renewal(
    records: Iterable[TrainingCertificate], today: date, days: int = 30
) -> list[str]:
    return sorted({r.driver_id for r in records if r.lapses_within(days, today)})
