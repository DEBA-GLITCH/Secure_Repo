# backend/app/agent/state.py
from typing import TypedDict, Optional
from app.agent.tools.schemas import Finding, FileAnalysisResult


class AgentState(TypedDict):
    # ── input (set once at the start, never changes) ──────────
    job_id: str
    repo_url: str
    repo_name: str        # "owner/repo"
    commit_sha: str
    github_token: str
    is_private: bool

    # ── fetcher node output ────────────────────────────────────
    # list of files that passed the extension/size filter
    # each item is a dict with: path, size, sha (from GitHub tree API)
    scannable_files: list[dict]
    total_files: int       # total files in repo (before filter)

    # ── prefilter node output ──────────────────────────────────
    # files that scored above 0 on regex/AST pre-scan
    # these are what actually go to the LLM
    flagged_files: list[FileAnalysisResult]

    # ── analyzer node output ───────────────────────────────────
    # all findings from ALL layers (regex + ast + llm)
    all_findings: list[Finding]

    # ── aggregator node output ─────────────────────────────────
    # deduplicated, sorted, enriched findings
    final_findings: list[Finding]

    # ── reporter node output ───────────────────────────────────
    report: Optional[dict]

    # ── control flow ───────────────────────────────────────────
    error: Optional[str]
    # if error is set, graph routes to failure handler
    # instead of continuing to next node

    current_node: str
    # tracks which node is running
    # used to update job status in Redis so frontend can show progress
    # e.g. "fetching files..." → "scanning..." → "generating report..."

    files_scanned: int
    # running counter — incremented as each file is analyzed
    # used for progress percentage on the frontend