# backend/app/agent/nodes/reporter.py
from datetime import datetime
from app.agent.state import AgentState
from app.agent.tools.schemas import Severity
from app.services.cache import get_cache


async def reporter_node(state: AgentState) -> AgentState:
    cache = get_cache()
    findings = state["final_findings"]

    # count by severity
    severity_counts = {s.value: 0 for s in Severity}
    for f in findings:
        severity_counts[f.severity.value] += 1

    # count by category
    category_counts: dict[str, int] = {}
    for f in findings:
        key = f.category.value
        category_counts[key] = category_counts.get(key, 0) + 1

    # compute overall risk score
    # weighted sum: critical=10, high=5, medium=2, low=1
    weights = {
        Severity.CRITICAL : 10,
        Severity.HIGH     : 5,
        Severity.MEDIUM   : 2,
        Severity.LOW      : 1,
        Severity.INFO     : 0,
    }
    raw_score = sum(weights[f.severity] for f in findings)
    # normalize to 0-100
    risk_score = min(raw_score, 100)

    report = {
        "repo_url"        : state["repo_url"],
        "repo_name"       : state["repo_name"],
        "commit_sha"      : state["commit_sha"],
        "scanned_at"      : datetime.utcnow().isoformat(),
        "total_files"     : state["total_files"],
        "files_scanned"   : state["files_scanned"],
        "risk_score"      : risk_score,
        "severity_counts" : severity_counts,
        "category_counts" : category_counts,
        "findings"        : [f.model_dump() for f in findings],
    }

    # update final job status in Redis
    await cache.set_job_status(state["job_id"], {
        "status"    : "completed",
        "message"   : "Scan complete",
        "risk_score": risk_score,
        "findings"  : len(findings),
    })

    return {
        **state,
        "report"      : report,
        "current_node": "reporter",
    }