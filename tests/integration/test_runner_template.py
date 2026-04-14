from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def _load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


INGEST = _load_module(
    "cloud_security_runner_ingest_handler_test",
    ROOT / "runners" / "aws-s3-sqs-detect" / "src" / "ingest_handler.py",
)
DETECT = _load_module(
    "cloud_security_runner_detect_handler_test",
    ROOT / "runners" / "aws-s3-sqs-detect" / "src" / "detect_handler.py",
)


class TestAwsS3SqsDetectRunner:
    def test_ingest_skill_command_requires_env(self, monkeypatch):
        monkeypatch.delenv("INGEST_SKILL_CMD", raising=False)
        try:
            INGEST._skill_command()
        except ValueError as exc:
            assert "INGEST_SKILL_CMD" in str(exc)
        else:
            raise AssertionError("expected INGEST_SKILL_CMD validation failure")

    def test_ingest_batches_lines_for_sqs_limits(self):
        batches = list(INGEST._batched([str(i) for i in range(23)], size=10))
        assert [len(batch) for batch in batches] == [10, 10, 3]

    def test_detect_extracts_uid_from_finding_info(self):
        record = {"finding_info": {"uid": "det-123"}, "metadata": {"uid": "meta-123"}}
        assert DETECT._extract_uid(record) == "det-123"

    def test_detect_falls_back_to_metadata_uid(self):
        record = {"metadata": {"uid": "meta-123"}}
        assert DETECT._extract_uid(record) == "meta-123"

    def test_detect_falls_back_to_event_uid(self):
        record = {"event_uid": "evt-123"}
        assert DETECT._extract_uid(record) == "evt-123"
