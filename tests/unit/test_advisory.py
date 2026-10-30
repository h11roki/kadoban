from datetime import UTC, datetime

import pytest

from app.domain.advisory import Advisory


def test_an_advisory_needs_times_with_a_time_zone() -> None:
    with pytest.raises(ValueError, match="タイムゾーン"):
        Advisory(
            cve_id="CVE-2024-21762",
            published=datetime(2024, 2, 9, 9, 15, tzinfo=UTC),
            last_modified=datetime(2024, 2, 10, 9, 15),
            status="Analyzed",
            nvd_ranges=(),
            cna_ranges=(),
        )
