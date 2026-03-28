# backend/app/agent/tools/rate_limit_checker.py
import re
from app.agent.tools.schemas import Finding, Severity, VulnCategory


# ── Presence patterns ─────────────────────────────────────────────────────────
# these are patterns that indicate rate limiting IS present
# if we find a route handler but NONE of these, we flag it

RATE_LIMIT_INDICATORS = [
    # Python libraries
    r"slowapi",
    r"flask_limiter",
    r"fastapi_limiter",
    r"RateLimiter",
    r"rate_limit",
    r"@limiter\.",
    r"Limiter\(",
    # decorator patterns
    r"@ratelimit",
    r"@rate_limit",
    r"@throttle",
    # generic patterns
    r"throttl",
    r"ratelimit",
    r"rate.limit",
    # JS/TS libraries
    r"express-rate-limit",
    r"rateLimit\(",
    r"rateLimiter",
    r"bottleneck",
    r"p-limit",
    # nginx / infrastructure comments
    r"limit_req",
    r"X-RateLimit",
]

# ── Route patterns ────────────────────────────────────────────────────────────
# these tell us "this file contains API endpoints"
# if it has routes but no rate limiting, that's the problem

ROUTE_INDICATORS = [
    # FastAPI / Flask
    r"@app\.(get|post|put|delete|patch)\s*\(",
    r"@router\.(get|post|put|delete|patch)\s*\(",
    r"@blueprint\.(get|post|put|delete|patch)\s*\(",
    # Express.js
    r"router\.(get|post|put|delete|patch)\s*\(",
    r"app\.(get|post|put|delete|patch)\s*\(",
    # Django urls
    r"path\s*\(['\"]",
    r"url\s*\(r['\"]",
]

# ── Auth endpoint patterns ─────────────────────────────────────────────────────
# auth endpoints with no rate limiting are especially dangerous
# unlimited login attempts = brute force attacks

AUTH_ENDPOINT_INDICATORS = [
    r"['\"/](login|signin|sign.in|authenticate|auth|token)['\"/]",
    r"def\s+(login|signin|authenticate|get_token)",
    r"async\s+def\s+(login|signin|authenticate|get_token)",
]

_COMPILED_RATE_LIMIT   = [(p, re.compile(p, re.IGNORECASE | re.MULTILINE)) for p in RATE_LIMIT_INDICATORS]
_COMPILED_ROUTES       = [(p, re.compile(p, re.IGNORECASE | re.MULTILINE)) for p in ROUTE_INDICATORS]
_COMPILED_AUTH         = [(p, re.compile(p, re.IGNORECASE | re.MULTILINE)) for p in AUTH_ENDPOINT_INDICATORS]


def check_rate_limiting(file_path: str, content: str) -> list[Finding]:
    findings: list[Finding] = []

    # step 1 — does this file have any routes at all?
    # if no routes, rate limiting is irrelevant for this file
    has_routes = any(
        compiled.search(content)
        for _, compiled in _COMPILED_ROUTES
    )

    if not has_routes:
        return []

    # step 2 — does this file have any rate limiting?
    has_rate_limit = any(
        compiled.search(content)
        for _, compiled in _COMPILED_RATE_LIMIT
    )

    # step 3 — does this file have auth endpoints specifically?
    has_auth_endpoints = any(
        compiled.search(content)
        for _, compiled in _COMPILED_AUTH
    )

    # step 4 — build findings based on what's absent
    if not has_rate_limit:
        # base finding — routes exist but no rate limiting anywhere
        severity = Severity.HIGH
        title    = "No Rate Limiting Detected on API Endpoints"
        description = (
            "This file contains API route handlers but no rate limiting "
            "was detected. Without rate limiting, endpoints are vulnerable to:\n"
            "- Brute force attacks (password guessing, token enumeration)\n"
            "- Denial of service (overwhelming the server with requests)\n"
            "- Scraping and data harvesting\n"
            "- AI agent runaway loops hitting your API infinitely"
        )
        fix = (
            "Add rate limiting to your routes:\n\n"
            "FastAPI (slowapi):\n"
            "  from slowapi import Limiter\n"
            "  from slowapi.util import get_remote_address\n"
            "  limiter = Limiter(key_func=get_remote_address)\n"
            "  @app.get('/endpoint')\n"
            "  @limiter.limit('10/minute')\n"
            "  async def endpoint(request: Request): ...\n\n"
            "Express.js:\n"
            "  const rateLimit = require('express-rate-limit')\n"
            "  const limiter = rateLimit({ windowMs: 60000, max: 10 })\n"
            "  app.use('/api/', limiter)"
        )

        # auth endpoints without rate limiting are critical not just high
        # unlimited login attempts = password brute force is trivial
        if has_auth_endpoints:
            severity = Severity.CRITICAL
            title    = "No Rate Limiting on Authentication Endpoints"
            description = (
                "Authentication endpoints (login, token generation) were found "
                "without any rate limiting. This allows unlimited password guessing "
                "attacks. An attacker can try millions of passwords per hour.\n\n"
                "This is one of the most commonly exploited vulnerabilities in "
                "web applications."
            )

        # find the first route line to point the user at
        first_route_line = _find_first_route_line(content)

        findings.append(Finding(
            file_path=file_path,
            line_start=first_route_line,
            line_end=None,
            # line_end=None because it's a file-level issue, not a single line
            category=VulnCategory.RATE_LIMIT_MISSING,
            severity=severity,
            confidence=0.8,
            title=title,
            description=description,
            masked_evidence=None,
            fix_suggestion=fix,
            code_snippet=None,
            detected_by="checklist",
        ))

    return findings


def _find_first_route_line(content: str) -> int:
    # finds the line number of the first route decorator
    # so we can point the user at the right place
    for _, compiled in _COMPILED_ROUTES:
        match = compiled.search(content)
        if match:
            return content[:match.start()].count("\n") + 1
    return 1


def get_rate_limit_suspicion_score(content: str) -> float:
    # files with routes but no rate limiting get a medium suspicion score
    # they need LLM to reason about context — maybe rate limiting is in middleware
    has_routes = any(
        compiled.search(content)
        for _, compiled in _COMPILED_ROUTES
    )
    has_rate_limit = any(
        compiled.search(content)
        for _, compiled in _COMPILED_RATE_LIMIT
    )

    if has_routes and not has_rate_limit:
        return 0.5
    return 0.0