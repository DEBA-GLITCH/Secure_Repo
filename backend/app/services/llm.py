# backend/app/services/llm.py
from openai import AsyncOpenAI
from langchain_groq import ChatGroq
from langchain_core.messages import SystemMessage, HumanMessage
from tenacity import (
    retry,
    stop_after_attempt,
    wait_exponential,
    retry_if_exception_type,
)
import httpx
from app.config import get_settings

settings = get_settings()


# ── Groq client (fast analysis) ───────────────────────────────────────────────

def get_groq_llm(temperature: float = 0.1) -> ChatGroq:
    # temperature=0.1 means very deterministic responses
    # security analysis needs consistency, not creativity
    # 0.0 = always same output, 1.0 = very random
    return ChatGroq(
        api_key=settings.groq_api_key,
        model=settings.groq_model_fast,
        temperature=temperature,
        # max_retries=2 means if Groq fails, langchain retries twice automatically
        max_retries=2,
    )


# ── OpenRouter client (deep reasoning) ────────────────────────────────────────

def get_openrouter_client() -> AsyncOpenAI:
    # OpenRouter uses the exact same API format as OpenAI
    # so we use the OpenAI SDK but point base_url at OpenRouter
    # this is why we installed openai SDK for a non-OpenAI provider
    return AsyncOpenAI(
        api_key=settings.openrouter_api_key,
        base_url=settings.openrouter_base_url,
        default_headers={
            # OpenRouter requires these headers to identify your app
            # shows up in their dashboard so you can track usage
            "HTTP-Referer": "https://securerepo.dev",
            "X-Title": "SecureRepo Security Scanner",
        },
    )


# ── Retry decorator ───────────────────────────────────────────────────────────
# tenacity: if the LLM call fails, retry with exponential backoff
# exponential backoff means: wait 1s, then 2s, then 4s between retries
# this handles rate limits and temporary API outages gracefully

def llm_retry(func):
    return retry(
        # retry on these specific exceptions only
        retry=retry_if_exception_type((
            httpx.TimeoutException,
            httpx.HTTPStatusError,
            Exception,
        )),
        # try 3 times total (1 original + 2 retries)
        stop=stop_after_attempt(3),
        # wait 1s after first failure, 2s after second, max 8s
        wait=wait_exponential(multiplier=1, min=1, max=8),
    )(func)


# ── Main LLM router ───────────────────────────────────────────────────────────

class LLMRouter:

    def __init__(self):
        self.groq = get_groq_llm()
        self.openrouter = get_openrouter_client()

    def should_use_deep_model(self, suspicion_score: float) -> bool:
        # this is the routing decision from our architecture discussion
        # suspicion_score comes from the pre-filter (regex + AST)
        # high score = file looks very suspicious = send to deep reasoning model
        # low score  = quick check is enough = send to fast Groq model
        return suspicion_score >= settings.llm_deep_analysis_threshold

    @llm_retry
    async def analyze_with_groq(
        self,
        system_prompt: str,
        code_content: str,
        file_path: str,
    ) -> str:
        # CRITICAL: we wrap code in XML tags
        # this is the prompt injection defense from Q7
        # the model is told in the system prompt that <code> is UNTRUSTED DATA
        # even if the code contains "ignore previous instructions", it's
        # structurally separated from the actual instructions
        messages = [
            SystemMessage(content=system_prompt),
            HumanMessage(content=(
                f"Analyze this file: {file_path}\n\n"
                f"<untrusted_code>\n{code_content}\n</untrusted_code>"
            )),
        ]
        response = await self.groq.ainvoke(messages)
        return response.content

    @llm_retry
    async def analyze_with_openrouter(
        self,
        system_prompt: str,
        code_content: str,
        file_path: str,
        model: str | None = None,
    ) -> str:
        # use specified model or fall back to default deep model
        target_model = model or settings.openrouter_model_deep

        response = await self.openrouter.chat.completions.create(
            model=target_model,
            temperature=0.1,
            messages=[
                {"role": "system", "content": system_prompt},
                {
                    "role": "user",
                    "content": (
                        f"Analyze this file: {file_path}\n\n"
                        f"<untrusted_code>\n{code_content}\n</untrusted_code>"
                    ),
                },
            ],
        )
        return response.choices[0].message.content

    async def analyze(
        self,
        system_prompt: str,
        code_content: str,
        file_path: str,
        suspicion_score: float = 0.0,
    ) -> tuple[str, str]:
        # main entry point — routes to correct model automatically
        # returns (response_text, model_used) so we know which model caught it
        if self.should_use_deep_model(suspicion_score):
            response = await self.analyze_with_openrouter(
                system_prompt, code_content, file_path
            )
            return response, f"llm_{settings.openrouter_model_deep.split('/')[0]}"
        else:
            response = await self.analyze_with_groq(
                system_prompt, code_content, file_path
            )
            return response, f"llm_groq"

    async def analyze_with_fallback(
        self,
        system_prompt: str,
        code_content: str,
        file_path: str,
        suspicion_score: float = 0.0,
    ) -> tuple[str, str]:
        # tries primary model, falls back to alternative if it fails
        # e.g. deepseek rate limited → falls back to qwen
        try:
            return await self.analyze(
                system_prompt, code_content, file_path, suspicion_score
            )
        except Exception as e:
            print(f"primary model failed: {e}, trying fallback")
            # fallback: use the alternative OpenRouter model
            response = await self.analyze_with_openrouter(
                system_prompt,
                code_content,
                file_path,
                model=settings.openrouter_model_alt,
            )
            return response, f"llm_fallback_{settings.openrouter_model_alt.split('/')[0]}"


# singleton
_router: LLMRouter | None = None


def get_llm_router() -> LLMRouter:
    global _router
    if _router is None:
        _router = LLMRouter()
    return _router