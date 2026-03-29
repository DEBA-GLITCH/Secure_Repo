# backend/app/agent/nodes/prefilter.py
import asyncio
from app.agent.state import AgentState
from app.agent.tools.schemas import FileAnalysisResult
from app.agent.tools.secret_scanner import scan_for_secrets, get_suspicion_score
from app.agent.tools.injection_detector import detect_injections, get_injection_suspicion_score
from app.agent.tools.rate_limit_checker import check_rate_limiting, get_rate_limit_suspicion_score
from app.agent.tools.auth_analyzer import analyze_auth, get_auth_suspicion_score
from app.agent.tools.ai_risk_scanner import scan_ai_risks, get_ai_risk_suspicion_score
from app.agent.tools.schemas import Finding
from app.services.github import GitHubClient, parse_repo_url
from app.services.cache import get_cache
from app.config import get_settings

settings = get_settings()

# how many files to fetch from GitHub concurrently
# too high = rate limited, too low = slow
CONCURRENT_FETCH_LIMIT = 3


async def prefilter_node(state: AgentState) -> AgentState:
    cache = get_cache()
    await cache.set_job_status(state["job_id"], {
        "status": "running",
        "current_node": "prefilter",
        "message": "Running security pre-scan...",
        "files_scanned": 0,
        "total_files": len(state["scannable_files"]),
    })

    owner, repo = parse_repo_url(state["repo_url"])
    client = GitHubClient(state["github_token"])

    # semaphore limits concurrent GitHub API calls
    # prevents rate limiting — 10 files at a time max
    semaphore = asyncio.Semaphore(CONCURRENT_FETCH_LIMIT)

    # regex findings found during pre-filter
    # these don't need LLM — regex is confident enough
    regex_findings: list[Finding] = []

    # files that need deeper LLM analysis
    flagged: list[FileAnalysisResult] = []

    async def process_file(file_info: dict):
        async with semaphore:
            path = file_info["path"]

            # fetch file content from GitHub
            content = await client.get_file_content(owner, repo, path)
            if content is None:
                return

            # run ALL regex/AST scanners on this file
            # these are fast — pure Python, no API calls
            secret_findings  = scan_for_secrets(path, content)
            inject_findings  = detect_injections(path, content)
            rate_findings    = check_rate_limiting(path, content)
            auth_findings    = analyze_auth(path, content)
            ai_findings      = scan_ai_risks(path, content)

            # collect all regex/AST findings
            all_file_findings = (
                secret_findings +
                inject_findings +
                rate_findings +
                auth_findings +
                ai_findings
            )
            regex_findings.extend(all_file_findings)

            # compute suspicion score — max across all scanners
            # a file only needs ONE scanner to be suspicious
            score = max(
                get_suspicion_score(content),
                get_injection_suspicion_score(content),
                get_rate_limit_suspicion_score(content),
                get_auth_suspicion_score(content),
                get_ai_risk_suspicion_score(content),
            )

            # detect language for LLM context
            ext = path.split(".")[-1].lower() if "." in path else ""
            lang_map = {
                "py": "python", "js": "javascript",
                "ts": "typescript", "go": "go",
                "rb": "ruby", "php": "php",
            }
            language = lang_map.get(ext, "unknown")

            # collect which patterns hit for LLM context
            regex_hits = [f.title for f in secret_findings + inject_findings]
            ast_hits   = [f.title for f in all_file_findings if f.detected_by == "ast"]

            # even if score is 0, if regex found something flag it for LLM
            # LLM can reason about whether it's a real issue or false positive
            if score > 0 or len(all_file_findings) > 0:
                flagged.append(FileAnalysisResult(
                    file_path=path,
                    content=content,
                    suspicion_score=score,
                    regex_hits=regex_hits,
                    ast_hits=ast_hits,
                    language=language,
                ))

    # process ALL files concurrently (respecting semaphore)
    files_to_scan = state["scannable_files"][:50]
    await asyncio.gather(*[
        process_file(f) for f in files_to_scan
    ])

    await client.close()

    # sort flagged files — highest suspicion first
    # so LLM analyzes the most suspicious files first
    flagged.sort(key=lambda x: x.suspicion_score, reverse=True)

    await cache.set_job_status(state["job_id"], {
        "status": "running",
        "current_node": "prefilter",
        "message": f"Pre-scan complete. {len(flagged)} suspicious files found.",
        "files_scanned": len(state["scannable_files"]),
        "total_files": len(state["scannable_files"]),
    })

    return {
        **state,
        "flagged_files": flagged,
        "all_findings": regex_findings,
        "current_node": "prefilter",
        "files_scanned": len(state["scannable_files"]),
    }