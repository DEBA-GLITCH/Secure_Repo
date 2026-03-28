# backend/app/agent/tools/injection_detector.py
import re
import ast
from dataclasses import dataclass, field
from app.agent.tools.schemas import Finding, Severity, VulnCategory


@dataclass
class InjectionPattern:
    name: str
    pattern: str
    category: VulnCategory
    severity: Severity
    title: str
    description: str
    fix: str
    # some patterns only make sense in certain languages
    languages: list[str] = field(default_factory=lambda: ["python", "javascript", "typescript", "any"])


INJECTION_PATTERNS: list[InjectionPattern] = [

    # ── SQL Injection ─────────────────────────────────────────────────────────
    InjectionPattern(
        name="SQL_STRING_CONCAT",
        # matches: "SELECT" + variable, or f"SELECT ... {variable}"
        pattern=r'(?i)(select|insert|update|delete|drop|union).{0,60}(\+\s*\w+|\{[^}]+\}|%s|format\()',
        category=VulnCategory.SQL_INJECTION,
        severity=Severity.CRITICAL,
        title="Potential SQL Injection via String Formatting",
        description=(
            "A SQL query is being constructed using string concatenation or "
            "formatting with what appears to be a variable. If this variable "
            "contains user input, attackers can manipulate the query to dump "
            "your entire database, bypass authentication, or delete data."
        ),
        fix=(
            "Use parameterized queries:\n"
            "  # WRONG:  query = 'SELECT * FROM users WHERE id = ' + user_id\n"
            "  # RIGHT:  cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))\n"
            "For ORMs use query builders, never raw string formatting."
        ),
    ),

    InjectionPattern(
        name="ORM_RAW_QUERY",
        # matches SQLAlchemy/Django raw() with string formatting
        pattern=r'(?i)(\.raw\(|text\(|execute\().{0,80}(%|format\(|f["\'])',
        category=VulnCategory.SQL_INJECTION,
        severity=Severity.HIGH,
        title="Raw ORM Query with String Formatting",
        description=(
            "A raw SQL query through an ORM is being constructed with string "
            "formatting. This bypasses the ORM's built-in SQL injection protection."
        ),
        fix=(
            "Use bound parameters with raw queries:\n"
            "  # SQLAlchemy: db.execute(text('SELECT * FROM t WHERE id = :id'), {'id': user_id})\n"
            "  # Django: Model.objects.raw('SELECT * WHERE id = %s', [user_id])"
        ),
    ),

    # ── Command Injection ─────────────────────────────────────────────────────
    InjectionPattern(
        name="OS_SYSTEM_CALL",
        # os.system(), os.popen(), subprocess with shell=True
        pattern=r'os\.(system|popen|exec[lv]pe?)\s*\(',
        category=VulnCategory.COMMAND_INJECTION,
        severity=Severity.CRITICAL,
        title="Dangerous OS Command Execution",
        description=(
            "os.system() or os.popen() is being used to execute shell commands. "
            "If any part of the command includes user input, an attacker can "
            "execute arbitrary commands on your server."
        ),
        fix=(
            "Use subprocess with a list (never shell=True with user input):\n"
            "  # WRONG:  os.system('convert ' + filename)\n"
            "  # RIGHT:  subprocess.run(['convert', filename], capture_output=True)\n"
            "Never pass user input to shell commands."
        ),
        languages=["python"],
    ),

    InjectionPattern(
        name="SUBPROCESS_SHELL_TRUE",
        pattern=r'subprocess\.(run|call|Popen|check_output).{0,200}shell\s*=\s*True',
        category=VulnCategory.COMMAND_INJECTION,
        severity=Severity.HIGH,
        title="subprocess with shell=True",
        description=(
            "subprocess is called with shell=True which passes the command "
            "through the shell interpreter. Combined with user input this "
            "enables command injection attacks."
        ),
        fix=(
            "Pass commands as a list and remove shell=True:\n"
            "  subprocess.run(['git', 'clone', url], capture_output=True)\n"
            "If you must use shell=True, never include user input in the command."
        ),
        languages=["python"],
    ),

    InjectionPattern(
        name="JS_EVAL",
        # eval() and Function() constructor in JS/TS
        pattern=r'\beval\s*\(|new\s+Function\s*\(',
        category=VulnCategory.COMMAND_INJECTION,
        severity=Severity.CRITICAL,
        title="Use of eval() or Function Constructor",
        description=(
            "eval() or new Function() executes arbitrary JavaScript. "
            "If the argument contains any user input, this is a "
            "critical code injection vulnerability."
        ),
        fix=(
            "Never use eval() with user input.\n"
            "For JSON parsing use JSON.parse() instead of eval().\n"
            "For dynamic code, reconsider the architecture entirely."
        ),
        languages=["javascript", "typescript"],
    ),

    InjectionPattern(
        name="JS_CHILD_PROCESS",
        pattern=r'exec\s*\(\s*[`\'"].*\$\{|execSync\s*\(\s*[`\'"].*\$\{',
        category=VulnCategory.COMMAND_INJECTION,
        severity=Severity.CRITICAL,
        title="Command Injection via Template Literal in exec()",
        description=(
            "A shell command is being constructed using template literals "
            "which likely include variables. If any variable comes from "
            "user input this is a command injection vulnerability."
        ),
        fix=(
            "Use execFile() with an arguments array instead of exec():\n"
            "  // WRONG: exec(`git clone ${userUrl}`)\n"
            "  // RIGHT: execFile('git', ['clone', userUrl])"
        ),
        languages=["javascript", "typescript"],
    ),

    # ── Path Traversal ────────────────────────────────────────────────────────
    InjectionPattern(
        name="PATH_TRAVERSAL",
        # open() with string concat or format using what looks like user input
        pattern=r'open\s*\(.{0,60}(\+\s*\w+|\{[^}]+\}|request\.|req\.|params|query)',
        category=VulnCategory.PATH_TRAVERSAL,
        severity=Severity.HIGH,
        title="Potential Path Traversal",
        description=(
            "A file is being opened using a path that may include user input. "
            "An attacker can use '../../../etc/passwd' style payloads to read "
            "arbitrary files on your server including config files with secrets."
        ),
        fix=(
            "Validate and sanitize file paths:\n"
            "  import os\n"
            "  safe_path = os.path.realpath(os.path.join(BASE_DIR, user_input))\n"
            "  if not safe_path.startswith(BASE_DIR):\n"
            "      raise ValueError('path traversal detected')"
        ),
        languages=["python"],
    ),

    # ── SSRF ──────────────────────────────────────────────────────────────────
    InjectionPattern(
        name="SSRF_REQUESTS",
        # requests.get/post with variable URL
        pattern=r'requests\.(get|post|put|delete|head)\s*\(\s*(?![\'"](http|https))[^,\)]{0,80}(request\.|req\.|params|query|url|endpoint)',
        category=VulnCategory.SSRF,
        severity=Severity.HIGH,
        title="Potential Server-Side Request Forgery (SSRF)",
        description=(
            "An HTTP request is being made to a URL that appears to come from "
            "user input. An attacker can point this at internal services "
            "(e.g. http://169.254.169.254 for AWS metadata) to steal "
            "credentials or attack internal infrastructure."
        ),
        fix=(
            "Validate URLs before making requests:\n"
            "  1. Whitelist allowed domains/IPs\n"
            "  2. Block private IP ranges (10.x, 192.168.x, 172.16.x, 169.254.x)\n"
            "  3. Use a URL validation library\n"
            "  4. Never make server-side requests to user-supplied URLs without validation"
        ),
    ),

    InjectionPattern(
        name="SSRF_HTTPX",
        pattern=r'httpx\.(get|post|AsyncClient).{0,200}(request\.|req\.|params|query|url|endpoint)',
        category=VulnCategory.SSRF,
        severity=Severity.HIGH,
        title="Potential SSRF via httpx",
        description="httpx is making requests to a URL that may come from user input.",
        fix="Validate and whitelist URLs before making outbound HTTP requests.",
    ),

    # ── Insecure Deserialization ───────────────────────────────────────────────
    InjectionPattern(
        name="PICKLE_LOADS",
        pattern=r'pickle\.loads?\s*\(',
        category=VulnCategory.INSECURE_DESERIAL,
        severity=Severity.CRITICAL,
        title="Insecure Deserialization via pickle",
        description=(
            "pickle.load() deserializes Python objects from bytes. "
            "If the input comes from an untrusted source, an attacker can "
            "craft a payload that executes arbitrary code during deserialization. "
            "This is a remote code execution vulnerability."
        ),
        fix=(
            "Never deserialize pickle data from untrusted sources.\n"
            "Use JSON for data exchange with external systems:\n"
            "  import json\n"
            "  data = json.loads(user_input)  # safe\n"
            "  data = pickle.loads(user_input)  # NEVER do this"
        ),
        languages=["python"],
    ),

    InjectionPattern(
        name="YAML_LOAD_UNSAFE",
        # yaml.load() without Loader= is unsafe, yaml.full_load is safe
        pattern=r'yaml\.load\s*\([^)]*\)',
        category=VulnCategory.INSECURE_DESERIAL,
        severity=Severity.HIGH,
        title="Unsafe YAML Deserialization",
        description=(
            "yaml.load() without a safe Loader can execute arbitrary Python "
            "code embedded in YAML. This is a known RCE vulnerability."
        ),
        fix=(
            "Use yaml.safe_load() instead:\n"
            "  # WRONG: yaml.load(data)\n"
            "  # RIGHT: yaml.safe_load(data)"
        ),
        languages=["python"],
    ),

    # ── ReDoS ─────────────────────────────────────────────────────────────────
    InjectionPattern(
        name="REDOS_NESTED_QUANTIFIERS",
        # catastrophic backtracking patterns: (a+)+ or (a*)*
        pattern=r'["\'].*(\(.*[\+\*].*\)[\+\*]|(\w+[\+\*]){3,}).*["\']',
        category=VulnCategory.REDOS,
        severity=Severity.MEDIUM,
        title="Potential ReDoS — Catastrophic Regex Backtracking",
        description=(
            "A regex pattern with nested quantifiers was detected. "
            "Patterns like (a+)+ can take exponential time on certain inputs, "
            "allowing an attacker to send a crafted string that freezes your "
            "server for minutes or hours (denial of service)."
        ),
        fix=(
            "Rewrite the regex to avoid nested quantifiers.\n"
            "Test your regex against adversarial inputs using: "
            "https://regex101.com (check the 'catastrophic backtracking' warning)\n"
            "Consider using a regex timeout library."
        ),
    ),
]

# compile all patterns once
_COMPILED: list[tuple[InjectionPattern, re.Pattern]] = [
    (p, re.compile(p.pattern, re.MULTILINE | re.DOTALL))
    for p in INJECTION_PATTERNS
]


def detect_injections(file_path: str, content: str) -> list[Finding]:
    findings: list[Finding] = []

    # detect language from file extension
    # used to skip patterns irrelevant to the language
    ext = file_path.split(".")[-1].lower() if "." in file_path else ""
    lang = _detect_language(ext)

    for pattern_def, compiled in _COMPILED:
        # skip patterns that don't apply to this language
        if lang not in pattern_def.languages and "any" not in pattern_def.languages:
            continue

        matches = list(compiled.finditer(content))
        if not matches:
            continue

        # deduplicate — if same pattern matches 10 times in same file
        # report once with the first occurrence, not 10 separate findings
        # the description already says "was found in source code"
        first_match = matches[0]
        line_number = content[:first_match.start()].count("\n") + 1

        lines = content.splitlines()
        snippet_start = max(0, line_number - 2)
        snippet_end   = min(len(lines), line_number + 2)
        snippet       = "\n".join(lines[snippet_start:snippet_end])

        # if multiple occurrences, mention it in the title
        title = pattern_def.title
        if len(matches) > 1:
            title = f"{pattern_def.title} ({len(matches)} occurrences)"

        finding = Finding(
            file_path=file_path,
            line_start=line_number,
            line_end=line_number,
            category=pattern_def.category,
            severity=pattern_def.severity,
            confidence=0.75,
            # injection patterns are slightly lower confidence than secrets
            # because context matters more — not every string concat is injectable
            title=title,
            description=pattern_def.description,
            masked_evidence=first_match.group(0)[:80],
            fix_suggestion=pattern_def.fix,
            code_snippet=snippet,
            detected_by="regex",
        )
        findings.append(finding)

    # also run AST analysis for Python files
    # AST is more precise than regex for Python-specific patterns
    if lang == "python":
        ast_findings = _ast_scan_python(file_path, content)
        findings.extend(ast_findings)

    return findings


def _detect_language(ext: str) -> str:
    mapping = {
        "py": "python",
        "js": "javascript",
        "ts": "typescript",
        "jsx": "javascript",
        "tsx": "typescript",
        "rb": "ruby",
        "php": "php",
        "go": "go",
        "java": "java",
    }
    return mapping.get(ext, "any")


def _ast_scan_python(file_path: str, content: str) -> list[Finding]:
    # Python AST scanner — more precise than regex
    # parses the actual code structure so we catch things regex misses
    findings: list[Finding] = []

    try:
        tree = ast.parse(content)
    except SyntaxError:
        # file has syntax errors — can't parse, skip AST scan
        return []

    for node in ast.walk(tree):

        # detect: exec(user_input) — arbitrary code execution
        if isinstance(node, ast.Call):
            func_name = ""
            if isinstance(node.func, ast.Name):
                func_name = node.func.id
            elif isinstance(node.func, ast.Attribute):
                func_name = node.func.attr

            if func_name == "exec":
                findings.append(Finding(
                    file_path=file_path,
                    line_start=node.lineno,
                    line_end=node.lineno,
                    category=VulnCategory.COMMAND_INJECTION,
                    severity=Severity.CRITICAL,
                    confidence=0.9,
                    title="Use of exec() — Arbitrary Code Execution Risk",
                    description=(
                        "exec() executes arbitrary Python code from a string. "
                        "If the argument includes any user input this is a "
                        "critical remote code execution vulnerability."
                    ),
                    masked_evidence=f"exec() at line {node.lineno}",
                    fix_suggestion=(
                        "Remove exec() entirely. Reconsider the architecture.\n"
                        "If you need dynamic behavior, use a whitelist of "
                        "allowed operations instead of executing arbitrary code."
                    ),
                    detected_by="ast",
                ))

        # detect: assert used for security checks
        # assert statements are stripped in optimized mode (python -O)
        # so assert user.is_admin() is NOT a reliable auth check
        if isinstance(node, ast.Assert):
            findings.append(Finding(
                file_path=file_path,
                line_start=node.lineno,
                line_end=node.lineno,
                category=VulnCategory.BROKEN_AUTH,
                severity=Severity.HIGH,
                confidence=0.7,
                title="assert Used for Security Check",
                description=(
                    "An assert statement is being used which may be a security check. "
                    "assert statements are completely removed when Python runs with "
                    "the -O (optimize) flag, meaning this check can be silently bypassed."
                ),
                masked_evidence=f"assert at line {node.lineno}",
                fix_suggestion=(
                    "Replace assert with an explicit if/raise:\n"
                    "  # WRONG: assert user.is_admin()\n"
                    "  # RIGHT: if not user.is_admin(): raise PermissionError('unauthorized')"
                ),
                detected_by="ast",
            ))

    return findings


def get_injection_suspicion_score(content: str) -> float:
    hit_count = sum(
        1 for _, compiled in _COMPILED
        if compiled.search(content)
    )
    return min(hit_count / 3.0, 1.0)