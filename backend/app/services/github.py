# backend/app/services/github.py
import httpx
from typing import Optional
from app.config import get_settings

settings = get_settings()

# file extensions we actually care about scanning
# everything else (images, fonts, lock files, compiled files) gets skipped
SCANNABLE_EXTENSIONS = {
    # backend languages
    ".py", ".js", ".ts", ".jsx", ".tsx",
    # config files — highest risk, devs love hardcoding secrets here
    ".env", ".yaml", ".yml", ".toml", ".ini", ".cfg", ".conf",
    # infrastructure
    ".tf", ".hcl",               # terraform
    ".dockerfile", "dockerfile", # docker
    # templates and web
    ".html", ".jinja", ".jinja2",
    # shell scripts
    ".sh", ".bash", ".zsh",
    # other languages
    ".go", ".rb", ".php", ".java", ".rs", ".cs",
    # data formats that sometimes contain secrets
    ".json",                     # but NOT package-lock.json, yarn.lock etc
}

# files to always skip even if extension matches
SKIP_FILENAMES = {
    "package-lock.json",
    "yarn.lock",
    "poetry.lock",
    "pipfile.lock",
    "composer.lock",
    "gemfile.lock",
    ".gitignore",
    ".prettierrc",
    ".eslintrc",
}


class GitHubClient:
    # base URL for GitHub REST API v3
    BASE_URL = "https://api.github.com"

    def __init__(self, access_token: str):
        self.access_token = access_token

        # httpx.AsyncClient = async HTTP client
        # we create it once per GitHubClient instance and reuse it
        # creating a new client per request is wasteful (TCP handshake every time)
        self.client = httpx.AsyncClient(
            base_url=self.BASE_URL,
            headers={
                # tells GitHub API which version to use
                "Accept": "application/vnd.github+json",
                # OAuth token — proves who the user is
                # "Bearer" is the token type for OAuth2
                "Authorization": f"Bearer {access_token}",
                "X-GitHub-Api-Version": "2022-11-28",
            },
            # if GitHub takes more than 30s to respond, give up
            # prevents your worker from hanging forever
            timeout=30.0,
            follow_redirects=True,
        )

    async def get_repo_info(self, owner: str, repo: str) -> dict:
        # fetches basic repo metadata
        # most importantly: the default branch name and latest commit SHA
        response = await self.client.get(f"/repos/{owner}/{repo}")
        response.raise_for_status()
        # raise_for_status() throws an exception if status is 4xx or 5xx
        # so you don't have to manually check response.status_code everywhere
        return response.json()

    async def get_latest_commit_sha(self, owner: str, repo: str, branch: str) -> str:
        # gets the SHA of the latest commit on the default branch
        # this is our cache key — same SHA = same code
        response = await self.client.get(
            f"/repos/{owner}/{repo}/commits/{branch}",
            params={"per_page": 1}
        )
        response.raise_for_status()
        data = response.json()
        return data["sha"]

    async def get_file_tree(self, owner: str, repo: str, sha: str) -> list[dict]:
        # this is the HYBRID approach you chose in Q1
        # one single API call returns the ENTIRE file tree recursively
        # without this we'd need one API call per directory = hundreds of requests
        response = await self.client.get(
            f"/repos/{owner}/{repo}/git/trees/{sha}",
            params={"recursive": "1"}
            # recursive=1 means go into every subdirectory
            # returns a flat list of every single file in the repo
        )
        response.raise_for_status()
        data = response.json()

        if data.get("truncated"):
            # GitHub truncates the tree if repo has 100,000+ files
            # extremely rare but worth logging
            print(f"WARNING: repo tree truncated for {owner}/{repo}")

        return data.get("tree", [])

    def filter_scannable_files(self, tree: list[dict]) -> list[dict]:
        # takes the raw tree from GitHub and returns only files worth scanning
        # this is the pre-filter step BEFORE we even look at content

        scannable = []

        for item in tree:
            # tree contains both files ("blob") and directories ("tree")
            # we only want files
            if item.get("type") != "blob":
                continue

            path: str = item.get("path", "")
            filename = path.split("/")[-1].lower()

            # skip always-ignored filenames
            if filename in SKIP_FILENAMES:
                continue

            # skip files that are too large
            # size is in bytes, convert to KB
            size_kb = item.get("size", 0) / 1024
            if size_kb > settings.max_file_size_kb:
                continue

            # check extension
            # handles files like "Dockerfile" with no extension
            ext = "." + path.split(".")[-1].lower() if "." in path else filename
            if ext not in SCANNABLE_EXTENSIONS and filename not in SCANNABLE_EXTENSIONS:
                continue

            scannable.append(item)

        return scannable

    async def get_file_content(self, owner: str, repo: str, path: str) -> Optional[str]:
        # fetches the actual content of a single file
        # called only on files that passed the filter — not every file
        try:
            response = await self.client.get(
                f"/repos/{owner}/{repo}/contents/{path}"
            )
            response.raise_for_status()
            data = response.json()

            # GitHub returns file content as base64 encoded string
            # we decode it to get the actual source code
            import base64
            content = base64.b64decode(data["content"]).decode("utf-8", errors="replace")
            # errors="replace" means if there's a weird byte (binary file snuck through)
            # replace it with ? instead of crashing
            return content

        except (httpx.HTTPStatusError, UnicodeDecodeError, KeyError):
            # file might be deleted between tree fetch and content fetch
            # or it might be a binary file that slipped through
            # either way, skip it gracefully
            return None

    async def close(self):
        # always close the HTTP client when done
        # releases the underlying TCP connections back to the OS
        await self.client.aclose()


def parse_repo_url(url: str) -> tuple[str, str]:
    # takes "https://github.com/owner/repo" or "github.com/owner/repo"
    # returns ("owner", "repo")
    url = url.rstrip("/")
    url = url.replace("https://", "").replace("http://", "")
    url = url.replace("github.com/", "")
    # remove .git suffix if present
    url = url.replace(".git", "")
    parts = url.split("/")

    if len(parts) < 2:
        raise ValueError(f"invalid GitHub URL: {url}")

    return parts[0], parts[1]