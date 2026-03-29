# backend/app/agent/nodes/aggregator.py
from app.agent.state import AgentState
from app.agent.tools.schemas import Finding, Severity


# severity order for sorting — critical first
SEVERITY_ORDER = {
    Severity.CRITICAL : 0,
    Severity.HIGH     : 1,
    Severity.MEDIUM   : 2,
    Severity.LOW      : 3,
    Severity.INFO     : 4,
}


async def aggregator_node(state: AgentState) -> AgentState:
    all_findings = state["all_findings"]

    # step 1 — deduplicate
    # same file + same category + same line = duplicate
    # happens when both regex AND LLM catch the same issue
    deduplicated = _deduplicate(all_findings)

    # step 2 — sort by severity then confidence
    # most critical, most confident findings first
    sorted_findings = sorted(
        deduplicated,
        key=lambda f: (
            SEVERITY_ORDER.get(f.severity, 99),
            -(f.confidence),
        )
    )

    return {
        **state,
        "final_findings": sorted_findings,
        "current_node": "aggregator",
    }


def _deduplicate(findings: list[Finding]) -> list[Finding]:
    seen: set[tuple] = set()
    unique: list[Finding] = []

    for f in findings:
        # dedup key: file + category + line
        key = (
            f.file_path,
            f.category.value,
            f.line_start or 0,
        )
        if key not in seen:
            seen.add(key)
            unique.append(f)

    return unique