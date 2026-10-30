from sqlalchemy import (
    Boolean,
    Column,
    Date,
    ForeignKey,
    Index,
    Integer,
    LargeBinary,
    MetaData,
    String,
    Table,
    Text,
)

metadata = MetaData()

exploited_vulnerabilities = Table(
    "exploited_vulnerabilities",
    metadata,
    Column("cve_id", String, primary_key=True),
    Column("date_added", Date, nullable=False),
    Column("due_date", Date, nullable=False),
    Column("used_by_ransomware", Boolean, nullable=False),
    Column("required_action", Text, nullable=False),
)

source_states = Table(
    "source_states",
    metadata,
    Column("source", String, primary_key=True),
    Column("version", String, nullable=False),
    Column("released_at", String, nullable=False),
    Column("synced_at", String, nullable=False),
)

cves = Table(
    "cves",
    metadata,
    Column("cve_id", String, primary_key=True),
    Column("published", String, nullable=False),
    Column("last_modified", String, nullable=False),
    Column("status", String, nullable=False),
    Column("original", LargeBinary, nullable=False),
)

nvd_ranges = Table(
    "nvd_ranges",
    metadata,
    Column("id", Integer, primary_key=True),
    Column("cve_id", String, nullable=False, index=True),
    Column("vendor", String, nullable=False),
    Column("product", String, nullable=False),
    Column("version", String, nullable=False),
    Column("start_including", String),
    Column("start_excluding", String),
    Column("end_including", String),
    Column("end_excluding", String),
    Column("conditional", Boolean, nullable=False),
    Index("ix_nvd_ranges_vendor_product", "vendor", "product"),
)

unreadable_cves = Table(
    "unreadable_cves",
    metadata,
    Column("cve_id", String, primary_key=True),
    Column("reason", Text, nullable=False),
    Column("seen_at", String, nullable=False),
)

cna_ranges = Table(
    "cna_ranges",
    metadata,
    Column("id", Integer, primary_key=True),
    Column("cve_id", String, nullable=False, index=True),
    Column("vendor", String),
    Column("product", String),
    Column("package_name", String),
    Column("default_status", String),
    Column("version", String),
    Column("status", String),
    Column("less_than", String),
    Column("less_than_or_equal", String),
    Column("version_type", String),
    Index("ix_cna_ranges_vendor_product", "vendor", "product"),
)

product_spellings = Table(
    "product_spellings",
    metadata,
    Column("id", Integer, primary_key=True),
    Column("source", String, nullable=False),
    Column("vendor", String, nullable=False),
    Column("product", String, nullable=False),
    Column("vendor_key", String, nullable=False),
    Column("product_key", String, nullable=False),
    Column("cve_count", Integer, nullable=False),
    Index("ix_product_spellings_keys", "vendor_key", "product_key"),
)

products = Table(
    "products",
    metadata,
    Column("id", Integer, primary_key=True),
    Column("company", String, nullable=False, index=True),
    Column("label", String, nullable=False),
    Column("version", String),
    Column("role", String, nullable=False),
    Column("maintainer", String),
    Column("registered_at", String, nullable=False),
)

product_keys = Table(
    "product_keys",
    metadata,
    Column("product_id", Integer, ForeignKey("products.id"), primary_key=True),
    Column("vendor_key", String, primary_key=True),
    Column("product_key", String, primary_key=True),
)
