from __future__ import annotations

from enum import Enum
from pathlib import Path
from typing import Any
from pydantic import BaseModel, Field


class Platform(str, Enum):
    sherlock = "sherlock"
    code4rena = "code4rena"
    codehawks = "codehawks"
    immunefi = "immunefi"
    generic = "generic"


class ContractInfo(BaseModel):
    name: str
    path: str
    inherits: list[str] = Field(default_factory=list)
    state_variables: list[str] = Field(default_factory=list)
    functions: list["FunctionInfo"] = Field(default_factory=list)


class FunctionInfo(BaseModel):
    contract: str
    name: str
    signature: str
    visibility: str | None = None
    modifiers: list[str] = Field(default_factory=list)
    payable: bool = False
    view_or_pure: bool = False
    body: str = ""
    line_start: int | None = None
    line_end: int | None = None


class StateTransition(BaseModel):
    contract: str
    function: str
    reads_storage: list[str] = Field(default_factory=list)
    writes_storage: list[str] = Field(default_factory=list)
    external_calls: list[str] = Field(default_factory=list)
    auth_requirements: list[str] = Field(default_factory=list)
    asset_movements: list[str] = Field(default_factory=list)
    emits: list[str] = Field(default_factory=list)
    timing_dependencies: list[str] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)


class EconomicPrimitive(BaseModel):
    name: str
    source_of_value: list[str] = Field(default_factory=list)
    sink_of_value: list[str] = Field(default_factory=list)
    reward_distribution: list[str] = Field(default_factory=list)
    timing_dependence: list[str] = Field(default_factory=list)
    external_price_dependency: list[str] = Field(default_factory=list)


class ProtocolModel(BaseModel):
    root: str
    contracts: list[ContractInfo] = Field(default_factory=list)
    actors: list[str] = Field(default_factory=list)
    privileged_roles: list[str] = Field(default_factory=list)
    assets: list[str] = Field(default_factory=list)
    accounting_systems: list[str] = Field(default_factory=list)
    integrations: list[str] = Field(default_factory=list)
    trust_assumptions: list[str] = Field(default_factory=list)
    economic_primitives: list[EconomicPrimitive] = Field(default_factory=list)


class InvariantCandidate(BaseModel):
    id: str
    title: str
    description: str
    related_contracts: list[str] = Field(default_factory=list)
    related_functions: list[str] = Field(default_factory=list)
    category: str
    confidence: str = "medium"
    attack_questions: list[str] = Field(default_factory=list)
    foundry_hint: str | None = None


class ScannerSignal(BaseModel):
    tool: str
    check: str
    severity: str | None = None
    title: str
    description: str = ""
    contract: str | None = None
    function: str | None = None
    path: str | None = None
    line: int | None = None
    raw: dict[str, Any] = Field(default_factory=dict)


class ExploitabilityAssessment(BaseModel):
    realistic: bool = False
    profitable: bool = False
    permissionless: bool = False
    repeatable: bool = False
    impact_material: bool = False
    invalid_reasons: list[str] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)

    @property
    def likely_valid(self) -> bool:
        return self.realistic and self.permissionless and self.impact_material and not self.invalid_reasons


class FindingCandidate(BaseModel):
    id: str
    title: str
    hypothesis: str
    source: str
    related_signals: list[ScannerSignal] = Field(default_factory=list)
    related_invariants: list[str] = Field(default_factory=list)
    related_transitions: list[str] = Field(default_factory=list)
    assessment: ExploitabilityAssessment
    severity_guess: str = "informational"
    next_validation_steps: list[str] = Field(default_factory=list)
    foundry_test_stub: str | None = None


class AnalysisResult(BaseModel):
    platform: Platform
    model: ProtocolModel
    transitions: list[StateTransition]
    invariants: list[InvariantCandidate]
    scanner_signals: list[ScannerSignal]
    findings: list[FindingCandidate]
