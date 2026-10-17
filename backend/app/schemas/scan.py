from typing import Literal

from pydantic import BaseModel, Field, field_validator

import datetime


class ScanRequest(BaseModel):
    type: Literal["url", "message", "upi"]
    input: str = Field(min_length=1, max_length=2048)

    @field_validator("input", mode="before")
    @classmethod
    def _strip(cls, v):
        if isinstance(v, str):
            return v.strip()
        return v


class FindingOut(BaseModel):
    rule_code: str
    severity: int
    explanation: str


class ScanResponse(BaseModel):
    scan_id: str
    type: str
    risk_score: int
    verdict: str
    summary: str
    findings: list[FindingOut]
    redirect_chain: list[str]
    notes: list[str]


class ScanHistoryOut(BaseModel):
    id: str
    type: str
    risk_score: int
    verdict: str
    created_at: datetime.datetime
