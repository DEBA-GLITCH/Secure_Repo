# backend/app/workers/scan_worker.py
import json
from datetime import datetime
from sqlalchemy import update
from app.agent.graph import get_graph
from app.agent.state import AgentState
from app.db.session import AsyncSessionLocal
from app.db.models import ScanJob, Finding as FindingModel, ScanStatus
from app.services.cache import get_cache
from app.config import get_settings

settings = get_settings()


async def run_scan(ctx: dict, job_id: str, initial_state: dict) -> dict:
    # ctx is the ARQ worker context — contains redis connection etc
    # job_id is the UUID of the ScanJob in postgres
    # initial_state is the AgentState dict to kick off the graph

    cache  = get_cache()
    graph  = get_graph()

    async with AsyncSessionLocal() as db:
        try:
            # ── mark job as running ───────────────────────────────
            await db.execute(
                update(ScanJob)
                .where(ScanJob.id == job_id)
                .values(
                    status     = ScanStatus.RUNNING,
                    started_at = datetime.utcnow(),
                )
            )
            await db.commit()

            # ── run the full agent graph ──────────────────────────
            # this is where fetcher → prefilter → analyzer →
            # aggregator → reporter all execute in sequence
            final_state: AgentState = await graph.ainvoke(
                initial_state,
                config={
                    # max steps before LangGraph force-stops the graph
                    # prevents infinite loops at the graph level
                    "recursion_limit": 50,
                }
            )

            # ── check for errors ──────────────────────────────────
            if final_state.get("error"):
                raise Exception(final_state["error"])

            # ── persist findings to postgres ──────────────────────
            report   = final_state["report"]
            findings = final_state["final_findings"]

            # bulk insert all findings
            finding_models = [
                FindingModel(
                    scan_job_id     = job_id,
                    file_path       = f.file_path,
                    line_start      = f.line_start,
                    line_end        = f.line_end,
                    category        = f.category.value,
                    severity        = f.severity.value,
                    confidence      = f.confidence,
                    title           = f.title,
                    description     = f.description,
                    masked_evidence = f.masked_evidence,
                    fix_suggestion  = f.fix_suggestion,
                    code_snippet    = f.code_snippet,
                    detected_by     = f.detected_by,
                )
                for f in findings
            ]

            db.add_all(finding_models)

            # ── mark job as completed ─────────────────────────────
            await db.execute(
                update(ScanJob)
                .where(ScanJob.id == job_id)
                .values(
                    status        = ScanStatus.COMPLETED,
                    completed_at  = datetime.utcnow(),
                    scanned_files = final_state.get("files_scanned", 0),
                )
            )
            await db.commit()

            # ── cache the result by commit SHA ────────────────────
            # next user who scans same commit gets instant results
            await cache.set_scan_result(
                repo_url   = initial_state["repo_url"],
                commit_sha = initial_state["commit_sha"],
                result     = {
                    "job_id"  : job_id,
                    "report"  : report,
                }
            )

            return {"status": "completed", "findings": len(findings)}

        except Exception as e:
            # ── mark job as failed ────────────────────────────────
            error_msg = str(e)
            await db.execute(
                update(ScanJob)
                .where(ScanJob.id == job_id)
                .values(
                    status        = ScanStatus.FAILED,
                    error_message = error_msg,
                    completed_at  = datetime.utcnow(),
                )
            )
            await db.commit()

            await cache.set_job_status(job_id, {
                "status"  : "failed",
                "message" : error_msg,
            })

            # re-raise so ARQ knows the job failed
            # ARQ will log it and optionally retry
            raise