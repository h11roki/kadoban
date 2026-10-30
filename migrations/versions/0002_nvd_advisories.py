from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0002"
down_revision: str | Sequence[str] | None = "0001"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "cna_ranges",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("cve_id", sa.String(), nullable=False),
        sa.Column("vendor", sa.String(), nullable=True),
        sa.Column("product", sa.String(), nullable=True),
        sa.Column("package_name", sa.String(), nullable=True),
        sa.Column("default_status", sa.String(), nullable=True),
        sa.Column("version", sa.String(), nullable=True),
        sa.Column("status", sa.String(), nullable=True),
        sa.Column("less_than", sa.String(), nullable=True),
        sa.Column("less_than_or_equal", sa.String(), nullable=True),
        sa.Column("version_type", sa.String(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )
    with op.batch_alter_table("cna_ranges", schema=None) as batch_op:
        batch_op.create_index(batch_op.f("ix_cna_ranges_cve_id"), ["cve_id"], unique=False)
        batch_op.create_index("ix_cna_ranges_vendor_product", ["vendor", "product"], unique=False)

    op.create_table(
        "cves",
        sa.Column("cve_id", sa.String(), nullable=False),
        sa.Column("published", sa.String(), nullable=False),
        sa.Column("last_modified", sa.String(), nullable=False),
        sa.Column("status", sa.String(), nullable=False),
        sa.Column("original", sa.LargeBinary(), nullable=False),
        sa.PrimaryKeyConstraint("cve_id"),
    )
    op.create_table(
        "nvd_ranges",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("cve_id", sa.String(), nullable=False),
        sa.Column("vendor", sa.String(), nullable=False),
        sa.Column("product", sa.String(), nullable=False),
        sa.Column("version", sa.String(), nullable=False),
        sa.Column("start_including", sa.String(), nullable=True),
        sa.Column("start_excluding", sa.String(), nullable=True),
        sa.Column("end_including", sa.String(), nullable=True),
        sa.Column("end_excluding", sa.String(), nullable=True),
        sa.Column("conditional", sa.Boolean(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    with op.batch_alter_table("nvd_ranges", schema=None) as batch_op:
        batch_op.create_index(batch_op.f("ix_nvd_ranges_cve_id"), ["cve_id"], unique=False)
        batch_op.create_index("ix_nvd_ranges_vendor_product", ["vendor", "product"], unique=False)

    op.create_table(
        "unreadable_cves",
        sa.Column("cve_id", sa.String(), nullable=False),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("seen_at", sa.String(), nullable=False),
        sa.PrimaryKeyConstraint("cve_id"),
    )


def downgrade() -> None:
    op.drop_table("unreadable_cves")
    with op.batch_alter_table("nvd_ranges", schema=None) as batch_op:
        batch_op.drop_index("ix_nvd_ranges_vendor_product")
        batch_op.drop_index(batch_op.f("ix_nvd_ranges_cve_id"))

    op.drop_table("nvd_ranges")
    op.drop_table("cves")
    with op.batch_alter_table("cna_ranges", schema=None) as batch_op:
        batch_op.drop_index("ix_cna_ranges_vendor_product")
        batch_op.drop_index(batch_op.f("ix_cna_ranges_cve_id"))

    op.drop_table("cna_ranges")
