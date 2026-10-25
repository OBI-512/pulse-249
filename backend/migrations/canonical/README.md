# Canonical clean-schema contract

The deployed Alembic chain remains immutable through `0011_typed_settings`.
For a clean installation, run the chain against a new PostgreSQL database,
then seed it with `python scripts/seed_demo_data.py`.  The isolated validator
checks that result against the static, explicit `schema_contract.py` inventory
without relying on live SQLAlchemy metadata for the comparison.

`0001_initial_schema` predates this discipline and dynamically creates the
then-current metadata. It is retained only for compatibility with the live
chain; no new migration may use that mechanism. A future distribution can
replace the historical chain with a generated SQL bootstrap only as a clearly
documented major-version migration, never by editing the applied history.
