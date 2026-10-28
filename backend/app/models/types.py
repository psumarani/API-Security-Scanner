"""Column type helpers."""

from enum import Enum as PyEnum

from sqlalchemy import Enum


def enum_column(enum_cls: type[PyEnum], name: str) -> Enum:
    """Store enum *values* as short strings with a CHECK constraint (portable, no PG enum DDL)."""
    return Enum(
        enum_cls,
        name=name,
        native_enum=False,
        length=32,
        create_constraint=True,
        validate_strings=True,
        values_callable=lambda members: [m.value for m in members],
    )
