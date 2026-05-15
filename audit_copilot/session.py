from __future__ import annotations

from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field


class InvalidatedHypothesis(BaseModel):
    id: str
    reason: str


class ConfirmedAttackVector(BaseModel):
    pattern: str
    reason: str


class AuditContext(BaseModel):
    """Project-local memory for a specific audit run."""

    invalidated_hypotheses: list[InvalidatedHypothesis] = Field(default_factory=list)
    confirmed_attack_vectors: list[ConfirmedAttackVector] = Field(default_factory=list)
    custom_invariants: list[str] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)


def load_audit_context(path: str | Path) -> AuditContext:
    context_path = Path(path)
    if not context_path.exists():
        return AuditContext()
    return AuditContext.model_validate_json(context_path.read_text())


def save_audit_context(context: AuditContext, path: str | Path) -> None:
    context_path = Path(path)
    context_path.parent.mkdir(parents=True, exist_ok=True)
    context_path.write_text(context.model_dump_json(indent=2) + "\n")


def mark_invalid(path: str | Path, hypothesis_id: str, reason: str) -> AuditContext:
    context = load_audit_context(path)
    context.invalidated_hypotheses = [
        item for item in context.invalidated_hypotheses if item.id != hypothesis_id
    ]
    context.invalidated_hypotheses.append(InvalidatedHypothesis(id=hypothesis_id, reason=reason))
    save_audit_context(context, path)
    return context


def confirm_attack_vector(path: str | Path, pattern: str, reason: str) -> AuditContext:
    context = load_audit_context(path)
    context.confirmed_attack_vectors = [
        item for item in context.confirmed_attack_vectors if item.pattern != pattern
    ]
    context.confirmed_attack_vectors.append(ConfirmedAttackVector(pattern=pattern, reason=reason))
    save_audit_context(context, path)
    return context


def add_invariant(path: str | Path, invariant: str) -> AuditContext:
    context = load_audit_context(path)
    normalized = invariant.strip()
    if normalized and normalized not in context.custom_invariants:
        context.custom_invariants.append(normalized)
    save_audit_context(context, path)
    return context


def add_note(path: str | Path, note: str) -> AuditContext:
    context = load_audit_context(path)
    normalized = note.strip()
    if normalized:
        context.notes.append(normalized)
    save_audit_context(context, path)
    return context


def context_summary(context: AuditContext) -> dict[str, int]:
    return {
        "invalidated_hypotheses": len(context.invalidated_hypotheses),
        "confirmed_attack_vectors": len(context.confirmed_attack_vectors),
        "custom_invariants": len(context.custom_invariants),
        "notes": len(context.notes),
    }


def apply_context_to_hypotheses(hypotheses: list[Any], context: AuditContext) -> list[Any]:
    """Filter hypotheses using human feedback.

    Works with Pydantic hypothesis objects and plain dictionaries.
    """
    invalid_ids = {item.id for item in context.invalidated_hypotheses}
    confirmed_patterns = {item.pattern.lower() for item in context.confirmed_attack_vectors}

    filtered: list[Any] = []
    for hypothesis in hypotheses:
        hid = _get_field(hypothesis, "id", "")
        if hid in invalid_ids:
            continue

        if any(pattern in str(hid).lower() for pattern in confirmed_patterns):
            hypothesis = _boost_hypothesis(hypothesis)

        filtered.append(hypothesis)

    return filtered


def _get_field(obj: Any, field: str, default: Any = None) -> Any:
    if isinstance(obj, dict):
        return obj.get(field, default)
    return getattr(obj, field, default)


def _boost_hypothesis(obj: Any) -> Any:
    if isinstance(obj, dict):
        boosted = dict(obj)
        boosted["confidence"] = min(float(boosted.get("confidence", 0.5)) + 0.08, 1.0)
        return boosted

    if hasattr(obj, "model_copy"):
        confidence = min(float(getattr(obj, "confidence", 0.5)) + 0.08, 1.0)
        return obj.model_copy(update={"confidence": confidence})

    return obj
