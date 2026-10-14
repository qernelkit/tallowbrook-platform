"""Customer and contact records as the reporting service sees them."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum


class StatementDelivery(StrEnum):
    EMAIL = "email"
    PORTAL = "portal"
    SFTP = "sftp"


@dataclass(frozen=True)
class Contact:
    name: str
    email: str
    phone: str | None = None
    receives_statements: bool = True


@dataclass
class Customer:
    id: str
    tenant_id: str
    name: str
    billing_country: str
    delivery: StatementDelivery = StatementDelivery.EMAIL
    statement_passcode: str | None = None
    contacts: list[Contact] = field(default_factory=list)

    def statement_recipients(self) -> list[str]:
        return [c.email for c in self.contacts if c.receives_statements]

    def display_name(self) -> str:
        return f"{self.name} ({self.billing_country})"
