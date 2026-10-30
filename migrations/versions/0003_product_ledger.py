from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0003"
down_revision: str | Sequence[str] | None = "0002"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "product_spellings",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("source", sa.String(), nullable=False),
        sa.Column("vendor", sa.String(), nullable=False),
        sa.Column("product", sa.String(), nullable=False),
        sa.Column("vendor_key", sa.String(), nullable=False),
        sa.Column("product_key", sa.String(), nullable=False),
        sa.Column("cve_count", sa.Integer(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    with op.batch_alter_table("product_spellings", schema=None) as batch_op:
        batch_op.create_index(
            "ix_product_spellings_keys", ["vendor_key", "product_key"], unique=False
        )

    op.create_table(
        "products",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("company", sa.String(), nullable=False),
        sa.Column("label", sa.String(), nullable=False),
        sa.Column("version", sa.String(), nullable=True),
        sa.Column("role", sa.String(), nullable=False),
        sa.Column("maintainer", sa.String(), nullable=True),
        sa.Column("registered_at", sa.String(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    with op.batch_alter_table("products", schema=None) as batch_op:
        batch_op.create_index(batch_op.f("ix_products_company"), ["company"], unique=False)

    op.create_table(
        "product_keys",
        sa.Column("product_id", sa.Integer(), nullable=False),
        sa.Column("vendor_key", sa.String(), nullable=False),
        sa.Column("product_key", sa.String(), nullable=False),
        sa.ForeignKeyConstraint(
            ["product_id"],
            ["products.id"],
        ),
        sa.PrimaryKeyConstraint("product_id", "vendor_key", "product_key"),
    )


def downgrade() -> None:
    op.drop_table("product_keys")
    with op.batch_alter_table("products", schema=None) as batch_op:
        batch_op.drop_index(batch_op.f("ix_products_company"))

    op.drop_table("products")
    with op.batch_alter_table("product_spellings", schema=None) as batch_op:
        batch_op.drop_index("ix_product_spellings_keys")

    op.drop_table("product_spellings")
