# backend/app/api/routes/scan.py
import uuid
from arq import create_pool
from arq.connections import RedisSettings
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from pydantic import BaseModel

from app.db.session import get_db
from app.db.models import ScanJob, Finding as FindingModel, User
from app.services.cache import CacheService
from app.services.github import GitHubClient, parse_repo_url
from app.api.deps import get_current_user, get_cache_dep
from app.workers.arq_settings import WorkerSettings
from app.config import get_settings

settings = get_settings()
router   = APIRouter()


class ScanRequest(BaseModel):
    repo_url: str


@router.post("/scan")
async def create_scan(
    body          : ScanRequest,
    db            : AsyncSession      = Depends(get_db),
    current_user  : User              = Depends(get_current_user),
    cache         : CacheService      = Depends(get_cache_dep),
):
    # step 1 — parse and validate the repo URL
    try:
        owner, repo = parse_repo_url(body.repo_url)
    except ValueError:
        raise HTTPException(400, "invalid GitHub repo URL")

    # step 2 — get the latest commit SHA
    # this is our cache key — check cache before doing anything else
    client = GitHubClient(current_user.access_token)
    try:
        info       = await client.get_repo_info(owner, repo)
        branch     = info["default_branch"]
        commit_sha = await client.get_latest_commit_sha(owner, repo, branch)
        is_private = info["private"]
    except Exception as e:
        raise HTTPException(400, f"could not access repo: {e}")
    finally:
        await client.close()

    # step 3 — check cache
    # if same repo + same commit was already scanned, return instantly
    cached = await cache.get_scan_result(body.repo_url, commit_sha)
    if cached:
        return {
            "job_id"  : cached["job_id"],
            "status"  : "completed",
            "cached"  : True,
            "message" : "returning cached result for this commit",
        }

    # step 4 — create scan job in DB
    job_id = str(uuid.uuid4())
    job    = ScanJob(
        id         = job_id,
        user_id    = current_user.id,
        repo_url   = body.repo_url,
        repo_name  = f"{owner}/{repo}",
        commit_sha = commit_sha,
        is_private = is_private,
    )
    db.add(job)
    await db.commit()

    # step 5 — set initial status in Redis
    await cache.set_job_status(job_id, {
        "status" : "pending",
        "message": "scan queued",
    })

    # step 6 — enqueue the job in ARQ
    # this returns IMMEDIATELY — the actual scan runs in the worker process
    # this is the async job queue pattern from Q8
    redis_pool = await create_pool(WorkerSettings.redis_settings)
    await redis_pool.enqueue_job(
        "run_scan",
        job_id        = job_id,
        initial_state = {
            "job_id"        : job_id,
            "repo_url"      : body.repo_url,
            "repo_name"     : f"{owner}/{repo}",
            "commit_sha"    : commit_sha,
            "github_token"  : current_user.access_token,
            "is_private"    : is_private,
            "scannable_files": [],
            "total_files"   : 0,
            "flagged_files" : [],
            "all_findings"  : [],
            "final_findings": [],
            "report"        : None,
            "error"         : None,
            "current_node"  : "pending",
            "files_scanned" : 0,
        }
    )
    await redis_pool.aclose()

    # return job_id immediately — frontend polls /scan/{job_id}/status
    return {
        "job_id" : job_id,
        "status" : "pending",
        "cached" : False,
        "message": "scan started",
    }


@router.get("/scan/{job_id}/status")
async def get_scan_status(
    job_id      : str,
    cache       : CacheService = Depends(get_cache_dep),
    current_user: User         = Depends(get_current_user),
):
    # frontend polls this every 2 seconds while scan is running
    status = await cache.get_job_status(job_id)
    if not status:
        raise HTTPException(404, "job not found")
    return status


@router.get("/scan/{job_id}/results")
async def get_scan_results(
    job_id      : str,
    db          : AsyncSession = Depends(get_db),
    current_user: User         = Depends(get_current_user),
):
    # called once scan is complete to get full findings
    result = await db.execute(
        select(ScanJob).where(ScanJob.id == job_id)
    )
    job = result.scalar_one_or_none()

    if not job:
        raise HTTPException(404, "scan job not found")

    # ownership check — users can only see their own scans
    # this is the IDOR prevention pattern from our taxonomy
    if str(job.user_id) != str(current_user.id):
        raise HTTPException(403, "forbidden")

    # fetch findings
    findings_result = await db.execute(
        select(FindingModel).where(FindingModel.scan_job_id == job_id)
    )
    findings = findings_result.scalars().all()

    return {
        "job"     : {
            "id"           : str(job.id),
            "repo_url"     : job.repo_url,
            "repo_name"    : job.repo_name,
            "commit_sha"   : job.commit_sha,
            "status"       : job.status.value,
            "total_files"  : job.total_files,
            "scanned_files": job.scanned_files,
            "created_at"   : job.created_at.isoformat(),
            "completed_at" : job.completed_at.isoformat() if job.completed_at else None,
        },
        "findings": [
            {
                "id"            : str(f.id),
                "file_path"     : f.file_path,
                "line_start"    : f.line_start,
                "line_end"      : f.line_end,
                "category"      : f.category.value,
                "severity"      : f.severity.value,
                "confidence"    : f.confidence,
                "title"         : f.title,
                "description"   : f.description,
                "masked_evidence": f.masked_evidence,
                "fix_suggestion": f.fix_suggestion,
                "detected_by"   : f.detected_by,
            }
            for f in findings
        ],
    }