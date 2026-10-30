from collections.abc import Iterator
from datetime import date

import httpx
import pytest
import respx

from app.application.ports import AdvisorySourceError
from app.domain.exploited import ExploitedCatalog, ExploitedVulnerability
from app.infrastructure.kev import KEV_URL, CisaKevCatalog


def entry(cve_id: str, ransomware: str) -> dict[str, object]:
    return {
        "cveID": cve_id,
        "vendorProject": "Fortinet",
        "product": "FortiOS",
        "dateAdded": "2024-02-09",
        "dueDate": "2024-02-16",
        "knownRansomwareCampaignUse": ransomware,
        "requiredAction": "Apply mitigations per vendor instructions.",
        "notes": "",
        "cwes": ["CWE-787"],
    }


@pytest.fixture
def kev() -> Iterator[respx.Route]:
    with respx.mock(assert_all_called=True) as router:
        yield router.get(KEV_URL)


def fetch() -> ExploitedCatalog:
    with httpx.Client() as client:
        return CisaKevCatalog(client).fetch()


def test_the_catalog_is_read_with_its_version_dates_and_ransomware_use(kev: respx.Route) -> None:
    kev.respond(
        json={
            "catalogVersion": "2026.10.29",
            "count": 2,
            "vulnerabilities": [
                entry("CVE-2024-21762", "Known"),
                entry("CVE-2099-0001", "Unknown"),
            ],
        }
    )

    catalog = fetch()

    assert catalog.version == "2026.10.29"
    assert catalog.vulnerabilities == (
        ExploitedVulnerability(
            cve_id="CVE-2024-21762",
            date_added=date(2024, 2, 9),
            due_date=date(2024, 2, 16),
            used_by_ransomware=True,
            required_action="Apply mitigations per vendor instructions.",
        ),
        ExploitedVulnerability(
            cve_id="CVE-2099-0001",
            date_added=date(2024, 2, 9),
            due_date=date(2024, 2, 16),
            used_by_ransomware=False,
            required_action="Apply mitigations per vendor instructions.",
        ),
    )


def test_a_server_error_is_a_source_error(kev: respx.Route) -> None:
    kev.respond(status_code=503)

    with pytest.raises(AdvisorySourceError, match="取れなかった"):
        fetch()


def test_an_unknown_ransomware_value_is_a_changed_format(kev: respx.Route) -> None:
    kev.respond(json={"catalogVersion": "x", "vulnerabilities": [entry("CVE-1", "Maybe")]})

    with pytest.raises(AdvisorySourceError, match="形が変わっている"):
        fetch()


def test_a_missing_field_is_a_changed_format(kev: respx.Route) -> None:
    broken = entry("CVE-1", "Known")
    del broken["dueDate"]
    kev.respond(json={"catalogVersion": "x", "vulnerabilities": [broken]})

    with pytest.raises(AdvisorySourceError, match="形が変わっている"):
        fetch()


def test_a_body_that_is_not_json_is_a_changed_format(kev: respx.Route) -> None:
    kev.respond(text="<html>maintenance</html>")

    with pytest.raises(AdvisorySourceError, match="形が変わっている"):
        fetch()
