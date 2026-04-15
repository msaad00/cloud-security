import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PACK_DIR = ROOT / "packs" / "lateral-movement"
SNOWFLAKE_SQL = PACK_DIR / "snowflake.sql"
DATABRICKS_SQL = PACK_DIR / "databricks.sql"
PACK_README = PACK_DIR / "README.md"
EXPECTED_COLUMNS = PACK_DIR / "golden" / "expected_columns.json"
EXPECTED_COLUMN_TYPES = PACK_DIR / "golden" / "expected_column_types.json"
EXPECTED_DATABRICKS_COLUMN_TYPES = PACK_DIR / "golden" / "expected_column_types_databricks.json"


def test_lateral_movement_pack_files_exist() -> None:
    assert PACK_DIR.is_dir()
    assert SNOWFLAKE_SQL.is_file()
    assert DATABRICKS_SQL.is_file()
    assert PACK_README.is_file()
    assert EXPECTED_COLUMNS.is_file()
    assert EXPECTED_COLUMN_TYPES.is_file()
    assert EXPECTED_DATABRICKS_COLUMN_TYPES.is_file()


def test_snowflake_pack_keeps_detector_contract() -> None:
    sql = SNOWFLAKE_SQL.read_text()

    for marker in (
        "IDENTIFIER($source_table)",
        "AssumeRole",
        "GenerateAccessToken",
        "MICROSOFT.AUTHORIZATION/ROLEASSIGNMENTS/WRITE",
        "activity_id = 6",
        "traffic_bytes >= 1024",
        "anchor.time_ms + 900000",
        "T1021",
        "T1078.004",
        "cloud-lateral-movement",
        "finding_json",
    ):
        assert marker in sql

    for cidr_pattern in (
        r"^10\\.",
        r"^192\\.168\\.",
        r"^172\\.(1[6-9]|2[0-9]|3[0-1])\\.",
        r"^100\\.(6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])\\.",
    ):
        assert cidr_pattern in sql


def test_snowflake_pack_emits_expected_columns() -> None:
    sql = SNOWFLAKE_SQL.read_text()
    expected_columns = json.loads(EXPECTED_COLUMNS.read_text())

    for column in expected_columns:
        assert re.search(rf"\bAS\s+{re.escape(column)}\b", sql, re.IGNORECASE), column


def test_snowflake_pack_locks_expected_column_types() -> None:
    sql = SNOWFLAKE_SQL.read_text()
    expected_column_types = json.loads(EXPECTED_COLUMN_TYPES.read_text())

    for column, column_type in expected_column_types.items():
        assert re.search(
            rf"::\s*{re.escape(column_type)}\s+AS\s+{re.escape(column)}\b",
            sql,
            re.IGNORECASE,
        ), column


def test_databricks_pack_keeps_detector_contract() -> None:
    sql = DATABRICKS_SQL.read_text()

    for marker in (
        "${source_table}",
        "${lookback_hours}",
        "AssumeRole",
        "GenerateAccessToken",
        "MICROSOFT.AUTHORIZATION/ROLEASSIGNMENTS/WRITE",
        "activity_id = 6",
        "traffic_bytes >= 1024",
        "anchor.time_ms + 900000",
        "T1021",
        "T1078.004",
        "cloud-lateral-movement",
        "TO_JSON",
        "NAMED_STRUCT",
        "-- sqlfluff:dialect:databricks",
    ):
        assert marker in sql

    for cidr_pattern in (
        r"^10\\.",
        r"^192\\.168\\.",
        r"^172\\.(1[6-9]|2[0-9]|3[0-1])\\.",
        r"^100\\.(6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])\\.",
    ):
        assert cidr_pattern in sql


def test_databricks_pack_emits_expected_columns() -> None:
    sql = DATABRICKS_SQL.read_text()
    expected_columns = json.loads(EXPECTED_COLUMNS.read_text())

    for column in expected_columns:
        assert re.search(rf"\bAS\s+{re.escape(column)}\b", sql, re.IGNORECASE), column


def test_databricks_pack_locks_expected_column_types() -> None:
    sql = DATABRICKS_SQL.read_text()
    expected_column_types = json.loads(EXPECTED_DATABRICKS_COLUMN_TYPES.read_text())

    for column, column_type in expected_column_types.items():
        if column == "finding_json":
            assert re.search(
                rf"CAST\(\s*TO_JSON\(.+?\)\s+AS\s+{re.escape(column_type)}\s*\)\s+AS\s+{re.escape(column)}\b",
                sql,
                re.IGNORECASE | re.DOTALL,
            ), column
            continue
        assert re.search(
            rf"CAST\(.+?\s+AS\s+{re.escape(column_type)}\)\s+AS\s+{re.escape(column)}\b",
            sql,
            re.IGNORECASE | re.DOTALL,
        ), column


def test_readme_describes_input_and_limits() -> None:
    readme = PACK_README.read_text()

    for phrase in (
        "raw_json VARIANT",
        "raw_json STRING",
        "15-minute correlation window",
        "traffic.bytes >= 1024",
        "OCSF-compatible Detection Finding",
        "databricks.sql",
        "sink-snowflake-jsonl",
    ):
        assert phrase in readme
