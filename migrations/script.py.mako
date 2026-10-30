<%!
def body(commands):
    lines = (commands or "").splitlines()
    kept = [line for line in lines if not line.lstrip().startswith("# ###")]
    return "\n".join(kept).strip() or "pass"
%>\
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
${imports if imports else ""}
revision: str = ${repr(up_revision)}
down_revision: str | Sequence[str] | None = ${repr(down_revision)}
branch_labels: str | Sequence[str] | None = ${repr(branch_labels)}
depends_on: str | Sequence[str] | None = ${repr(depends_on)}


def upgrade() -> None:
    ${body(upgrades)}


def downgrade() -> None:
    ${body(downgrades)}
