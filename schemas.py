"""JSON-serializable records for one sample analysis."""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field

LABELS = ("clean", "malicious", "inconclusive")
TYPES = ("clean", "pup", "trojan")
VERDICTS = LABELS
FAMILIES = (
    "none",
    "adware",
    "spyware",
    "banker",
    "dropper",
    "sms",
    "ransomware",
    "unknown",
)
CONFIDENCE = ("low", "medium", "high")
VERIFICATION_STATUS = ("supported", "unsupported", "insufficient")


@dataclass
class FileIdentity:
    name: str
    size: int
    md5: str
    sha1: str
    sha256: str


@dataclass
class Component:
    kind: str
    name: str
    exported: bool | None
    actions: list[str] = field(default_factory=list)
    decompile_path: str | None = None
    status: str = "pending"
    error: str | None = None


@dataclass
class NativeLib:
    apk: str
    abi: str
    name: str
    path: str
    size: int
    status: str
    functions: list[str] = field(default_factory=list)
    pseudocode: bool = False
    note: str | None = None
    jni_methods: list[str] = field(default_factory=list)


@dataclass
class Fingerprint:
    kind: str
    name: str
    sha256: str


@dataclass
class Payload:
    name: str
    kind: str
    via: str
    size: int
    detail: str


@dataclass
class SampleFacts:
    original: FileIdentity
    container: str
    base_apk: str | None
    members: list[FileIdentity]
    apks: list[FileIdentity]
    package: str | None
    version_name: str | None
    version_code: str | None
    app_label: str | None
    app_label_ref: str | None
    application_class: str | None
    permissions: list[str]
    components: list[Component]
    native_libs: list[NativeLib]
    stage_notes: list[str] = field(default_factory=list)
    framework: str = "android"
    framework_files: list[str] = field(default_factory=list)
    fingerprints: list[Fingerprint] = field(default_factory=list)
    payloads: list[Payload] = field(default_factory=list)


@dataclass
class Evidence:
    path: str
    symbol: str
    quote: str


@dataclass
class Finding:
    id: str
    behavior: str
    evidence: list[Evidence]
    confidence: str


@dataclass
class Verification:
    id: str
    status: str
    note: str


@dataclass
class Verdict:
    verdict: str
    family: str
    confidence: str
    summary: str
    supporting_finding_ids: list[str]
    malicious: bool = False
    malware_type: str = "none"


@dataclass
class Report:
    facts: SampleFacts
    hypotheses: list[Finding]
    verification: list[Verification]
    verdict: Verdict | None
    artifact_paths: list[str]
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


def file_identity_from_dict(data: dict) -> FileIdentity:
    return FileIdentity(
        name=data["name"],
        size=data["size"],
        md5=data["md5"],
        sha1=data["sha1"],
        sha256=data["sha256"],
    )


def report_from_dict(data: dict) -> Report:
    facts_raw = data["facts"]
    facts = SampleFacts(
        original=file_identity_from_dict(facts_raw["original"]),
        container=facts_raw["container"],
        base_apk=facts_raw.get("base_apk"),
        members=[file_identity_from_dict(item) for item in facts_raw.get("members", [])],
        apks=[file_identity_from_dict(item) for item in facts_raw.get("apks", [])],
        package=facts_raw.get("package"),
        version_name=facts_raw.get("version_name"),
        version_code=facts_raw.get("version_code"),
        app_label=facts_raw.get("app_label"),
        app_label_ref=facts_raw.get("app_label_ref"),
        application_class=facts_raw.get("application_class"),
        permissions=list(facts_raw.get("permissions", [])),
        components=[Component(**item) for item in facts_raw.get("components", [])],
        native_libs=[NativeLib(**item) for item in facts_raw.get("native_libs", [])],
        stage_notes=list(facts_raw.get("stage_notes", [])),
        framework=facts_raw.get("framework") or "android",
        framework_files=list(facts_raw.get("framework_files", [])),
        fingerprints=[Fingerprint(**item) for item in facts_raw.get("fingerprints", [])],
        payloads=[Payload(**item) for item in facts_raw.get("payloads", [])],
    )
    hypotheses = [
        Finding(
            id=item["id"],
            behavior=item["behavior"],
            confidence=item["confidence"],
            evidence=[Evidence(**ev) for ev in item.get("evidence", [])],
        )
        for item in data.get("hypotheses", [])
    ]
    verification = [Verification(**item) for item in data.get("verification", [])]
    verdict_raw = data.get("verdict")
    verdict = _verdict_from_dict(verdict_raw) if verdict_raw else None
    return Report(
        facts=facts,
        hypotheses=hypotheses,
        verification=verification,
        verdict=verdict,
        artifact_paths=list(data.get("artifact_paths", [])),
        errors=list(data.get("errors", [])),
    )


def _verdict_from_dict(data: dict) -> Verdict:
    return Verdict(
        verdict=data.get("verdict", ""),
        family=data.get("family", "unknown"),
        confidence=data.get("confidence", "low"),
        summary=data.get("summary", ""),
        supporting_finding_ids=list(data.get("supporting_finding_ids") or []),
        malicious=bool(data.get("malicious", data.get("verdict") == "trojan")),
        malware_type=data.get("malware_type") or "none",
    )


_CATEGORY_TERMS = (
    ("ransomware", ("ransomware", "ransom note", "encrypts files", "file encryption")),
    ("banker", ("banker", "overlay attack", "steals password", "credit card")),
    ("sms", ("sms", "sendtextmessage", "sendsms", "text message")),
    ("spyware", ("spyware", "exfiltrat", "surveillance", "clipboard", "keylog", "remote access", "steals ")),
    ("dropper", (
        "dropper",
        "dexclassloader",
        "downloads a payload",
        "downloads an apk",
        "installs another app",
        "installs an apk",
        "hidden payload",
        "unpacked and loaded",
        "loads the real",
    )),
    ("adware", ("adware", "advertis", "aggressive ad", "popup ad", "banner ad")),
)
_TROJAN_FAMILIES = {"spyware", "banker", "sms", "ransomware"}
_TROJAN_TERMS = (
    "packer",
    "jiagu",
    "hidden payload",
    "concealed",
    "hides the real",
    "spoof the apk",
    "spoof the signature",
    "signature spoof",
    "signature-spoof",
    "dexclassloader",
)
_HIDDEN_ONLY = re.compile(r"obfuscat|control-flow|control flow|not confirmed|truncated")
_UNSHOWN = re.compile(
    r"\b(not visible|not confirmed|did not confirm|no payload|cannot be reviewed|could not be reviewed)\b"
)
_NEGATION = re.compile(r"\b(not|no|none|without|never|isn't|is not)\b")
_OLD_LEAD = re.compile(r"^(?:verdict|label|inconclusive|malicious|clean)\b[^.]*\.\s*", re.IGNORECASE)


def positive_text(text: str) -> str:
    """Drop sentences that deny a behavior, so a rejected claim cannot set a family."""
    kept: list[str] = []
    for sentence in re.split(r"[.\n]", text.lower()):
        if _NEGATION.search(sentence):
            continue
        kept.append(sentence)
    return "\n".join(kept)


def infer_category(text: str) -> str:
    """Pick a generic family from behavior that is actually described."""
    lowered = positive_text(text)
    for name, terms in _CATEGORY_TERMS:
        if any(term in lowered for term in terms):
            return name
    return ""


def align_summary(summary: str, label: str, sample_type: str, family: str) -> str:
    """Make the first sentence use the same label, type, and family as the fields."""
    body = _OLD_LEAD.sub("", summary.strip(), count=1).strip()
    lead = f"Label {label}, type {sample_type}, family {family}."
    return f"{lead} {body}".strip() if body else lead


def _behavior_text(findings: list[Finding] | None, supported_ids: list[str]) -> str:
    items = list(findings or [])
    supported = set(supported_ids)
    relevant = [item for item in items if item.id in supported] or items
    return "\n".join(item.behavior for item in relevant)


def _family_from_behavior(
    family: str, findings: list[Finding] | None, supported_ids: list[str]
) -> str:
    text = _behavior_text(findings, supported_ids)
    inferred = infer_category(text)
    if inferred:
        return inferred
    named = family if family in FAMILIES and family not in ("", "none", "unknown") else ""
    if named and named in text.lower():
        return named
    return "unknown"


def enforce_verdict(
    verdict: Verdict,
    supported_ids: list[str],
    verification: list[Verification] | None = None,
    findings: list[Finding] | None = None,
) -> tuple[Verdict, str | None]:
    """Label is clean, malicious, or inconclusive. Type is clean, pup, or trojan.

    A pup is labeled malicious. Family comes from finding text, not from a denied word in the summary.
    """
    supported = set(supported_ids)
    confidence = verdict.confidence if verdict.confidence in CONFIDENCE else "low"
    ids = [item for item in verdict.supporting_finding_ids if item in supported]
    checks = list(verification or [])
    unresolved = any(item.status == "insufficient" for item in checks)
    rejected_all = bool(checks) and all(item.status == "unsupported" for item in checks)
    raw_label = verdict.verdict
    raw_type = verdict.malware_type
    family = verdict.family if verdict.family in FAMILIES else "unknown"
    note = None

    if raw_type in TYPES and raw_label in LABELS:
        label = raw_label
        sample_type = raw_type
    elif raw_label in ("clean", "pup", "trojan"):
        sample_type = raw_label
        family = family if family not in ("", "none") else (
            raw_type if raw_type in FAMILIES else "unknown"
        )
        label = "malicious" if raw_label == "trojan" else "clean" if raw_label == "clean" else "inconclusive"
        note = "verdict fields were recorded with the label, type, and family split"
    else:
        sample_type = "pup"
        label = "inconclusive"
        note = "verdict label was invalid and was recorded as inconclusive"

    family = _family_from_behavior(family, findings, supported_ids)
    sure_clean = confidence == "high" and rejected_all and not unresolved and not supported_ids
    if sure_clean:
        return (
            Verdict(
                verdict="clean",
                family="none",
                confidence="high",
                summary=align_summary(
                    verdict.summary.strip() or "The verifier rejected every finding.",
                    "clean",
                    "clean",
                    "none",
                ),
                supporting_finding_ids=[],
                malicious=False,
                malware_type="clean",
            ),
            None,
        )

    if not ids:
        ids = [item for item in supported_ids]
    behavior = _behavior_text(findings, ids)
    lowered = positive_text(behavior)
    if ids:
        confidence = _raise_confidence(confidence, findings, ids)
        if _trojan_behavior(lowered, family):
            sample_type = "trojan"
        elif family == "adware" or "in-app updater" in lowered or "self-update" in lowered:
            sample_type = "pup"
        elif sample_type != "trojan":
            sample_type = "pup"
    concealed = _motive_unshown(behavior, lowered, family)
    if (
        sample_type == "trojan"
        and ids
        and confidence in ("medium", "high")
        and not unresolved
        and not concealed
    ):
        label = "malicious"
        sample_type = "trojan"
    elif sample_type == "trojan" and ids:
        label = "inconclusive"
        sample_type = "trojan"
        note = note or "the trojan behavior is not sure enough to label the sample malicious"
    elif ids and not _hidden_only(lowered):
        label = "malicious"
        sample_type = "pup"
    elif ids:
        label = "inconclusive"
        sample_type = "trojan"
        note = note or "the sample hides its code, but the behavior was not shown"
    else:
        label = "inconclusive"
        sample_type = "clean"
        note = note or "no supported finding, so the label stays inconclusive"
        ids = []
    if label == "clean":
        family = "none"
    elif label != "clean" and family == "none":
        family = "unknown"
    return (
        Verdict(
            verdict=label,
            family=family,
            confidence=confidence,
            summary=align_summary(verdict.summary, label, sample_type, family),
            supporting_finding_ids=ids,
            malicious=label == "malicious",
            malware_type=sample_type,
        ),
        note,
    )


def _raise_confidence(confidence: str, findings: list[Finding] | None, ids: list[str]) -> str:
    """Use the strongest supported finding. The model cannot set a higher confidence."""
    rank = {name: index for index, name in enumerate(CONFIDENCE)}
    chosen = [
        item.confidence
        for item in findings or []
        if item.id in set(ids) and item.confidence in rank
    ]
    if not chosen:
        return confidence if confidence in rank else "low"
    return max(chosen, key=lambda name: rank[name])


def _trojan_behavior(lowered: str, family: str) -> bool:
    return family in _TROJAN_FAMILIES or any(term in lowered for term in _TROJAN_TERMS)


def _hidden_only(lowered: str) -> bool:
    if infer_category(lowered) or _trojan_behavior(lowered, ""):
        return False
    return bool(_HIDDEN_ONLY.search(lowered))


def _motive_unshown(text: str, lowered: str, family: str) -> bool:
    if family in _TROJAN_FAMILIES | {"adware"} or "downloads an apk" in lowered:
        return False
    return bool(_UNSHOWN.search(text.lower()))


def present_verdict(report: dict) -> dict:
    """Show a stored verdict with the current label, type, and family meanings."""
    if not isinstance(report, dict) or not isinstance(report.get("verdict"), dict):
        return report
    findings = [
        Finding(
            id=str(item.get("id") or ""),
            behavior=str(item.get("behavior") or ""),
            evidence=[],
            confidence=str(item.get("confidence") or "low"),
        )
        for item in report.get("hypotheses") or []
        if isinstance(item, dict)
    ]
    verification = [
        Verification(
            id=str(item.get("id") or ""),
            status=str(item.get("status") or "insufficient"),
            note=str(item.get("note") or ""),
        )
        for item in report.get("verification") or []
        if isinstance(item, dict)
    ]
    supported = [item.id for item in verification if item.status == "supported"]
    fixed, _note = enforce_verdict(
        _verdict_from_dict(report["verdict"]), supported, verification, findings
    )
    shown = dict(report)
    shown["verdict"] = asdict(fixed)
    return shown
