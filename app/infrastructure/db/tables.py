from sqlalchemy import Boolean, Column, Date, MetaData, String, Table, Text

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
    Column("synced_at", String, nullable=False),
)
