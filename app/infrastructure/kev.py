from datetime import date
from typing import Literal

import httpx
from pydantic import BaseModel, Field, ValidationError

from app.application.ports import AdvisorySourceError
from app.domain.exploited import ExploitedCatalog, ExploitedVulnerability

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


class _KevEntry(BaseModel):
    cve_id: str = Field(alias="cveID")
    date_added: date = Field(alias="dateAdded")
    due_date: date = Field(alias="dueDate")
    known_ransomware_campaign_use: Literal["Known", "Unknown"] = Field(
        alias="knownRansomwareCampaignUse"
    )
    required_action: str = Field(alias="requiredAction")


class _KevDocument(BaseModel):
    catalog_version: str = Field(alias="catalogVersion")
    vulnerabilities: list[_KevEntry]


class CisaKevCatalog:
    def __init__(self, client: httpx.Client) -> None:
        self._client = client

    def fetch(self) -> ExploitedCatalog:
        try:
            response = self._client.get(KEV_URL)
            response.raise_for_status()
        except httpx.HTTPError as error:
            raise AdvisorySourceError(f"KEV を取れなかった: {error}") from error
        try:
            document = _KevDocument.model_validate_json(response.content)
        except ValidationError as error:
            raise AdvisorySourceError(f"KEV の形が変わっている: {error}") from error
        return ExploitedCatalog(
            version=document.catalog_version,
            vulnerabilities=tuple(
                ExploitedVulnerability(
                    cve_id=entry.cve_id,
                    date_added=entry.date_added,
                    due_date=entry.due_date,
                    used_by_ransomware=entry.known_ransomware_campaign_use == "Known",
                    required_action=entry.required_action,
                )
                for entry in document.vulnerabilities
            ),
        )
