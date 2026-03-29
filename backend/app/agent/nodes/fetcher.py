# backend/app/agent/nodes/fetcher.py
import asyncio
from app.agent.state import AgentState
from app.services.github import GitHubClient, parse_repo_url
from app.services.cache import get_cache
from app.config import get_settings

settings = get_settings()


async def fetcher_node(state: AgentState) -> AgentState:
    # update progress so frontend knows what's happening
    cache = get_cache()
    await cache.set_job_status(state["job_id"], {
        "status": "running",
        "current_node": "fetcher",
        "message": "Fetching repository file tree...",
        "files_scanned": 0,
        "total_files": 0,
    })

    try:
        owner, repo = parse_repo_url(state["repo_url"])
        client = GitHubClient(state["github_token"])

        # step 1 — get repo metadata (branch name etc)
        info = await client.get_repo_info(owner, repo)
        default_branch = info["default_branch"]

        # step 2 — get the full file tree in ONE API call
        # this is the hybrid approach from Q1
        tree = await client.get_file_tree(owner, repo, state["commit_sha"])

        # step 3 — filter to only scannable files
        scannable = client.filter_scannable_files(tree)

        # enforce hard cap — don't scan repos with insane file counts
        if len(scannable) > settings.max_files_per_scan:
            scannable = scannable[:settings.max_files_per_scan]

        await client.close()

        # update progress
        await cache.set_job_status(state["job_id"], {
            "status": "running",
            "current_node": "fetcher",
            "message": f"Found {len(scannable)} files to scan",
            "files_scanned": 0,
            "total_files": len(scannable),
        })

        return {
            **state,
            "scannable_files": scannable,
            "total_files": len(tree),
            "current_node": "fetcher",
            "error": None,
        }

    except Exception as e:
        return {
            **state,
            "error": f"fetcher failed: {str(e)}",
            "current_node": "fetcher",
            "scannable_files": [],
            "total_files": 0,
        }