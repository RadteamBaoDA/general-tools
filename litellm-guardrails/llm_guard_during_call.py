"""
LLM Guard During-Call Guardrail for LiteLLM

This guardrail runs IN PARALLEL with the LLM API call to:
- Scan input prompts using LLM Guard /analyze/prompt or /scan/prompt endpoint
- Provide lower latency by not blocking the LLM call
- Reject requests that violate security policies

Mode: during_call
Hook: async_moderation_hook

Note: This hook CANNOT modify input, only accept or reject.

LLM Guard API Documentation: https://protectai.github.io/llm-guard/api/overview/
LiteLLM Custom Guardrail: https://docs.litellm.ai/docs/proxy/guardrails/custom_guardrail
"""

import os
from typing import Any, Dict, List, Literal, Optional

from litellm._logging import verbose_proxy_logger
from litellm.integrations.custom_guardrail import CustomGuardrail
from litellm.llms.custom_httpx.http_handler import (
    get_async_httpx_client,
    httpxSpecialProvider,
)
from litellm.proxy._types import UserAPIKeyAuth


class LLMGuardDuringCallGuardrail(CustomGuardrail):
    """
    During-call guardrail that scans input in parallel with LLM API call.
    
    This guardrail:
    - Runs IN PARALLEL with the LLM API call
    - CANNOT modify input data
    - Can only ACCEPT or REJECT the request
    - Provides LOWER LATENCY than pre_call
    
    Use this for:
    - Fast input validation without blocking LLM call
    - Prompt injection detection
    - Toxicity detection
    - When you don't need to sanitize/modify input
    """
    
    def __init__(
        self,
        api_key: Optional[str] = None,
        api_base: Optional[str] = None,
        risk_threshold: float = 0.5,
        timeout: int = 10,
        scanners_suppress: Optional[List[str]] = None,
        fail_on_error: bool = True,
        use_scan_endpoint: bool = True,
        **kwargs,
    ):
        """
        Initialize the LLM Guard During-Call Guardrail.
        
        Args:
            api_key: API key for LLM Guard API authentication (optional)
            api_base: Base URL of the LLM Guard API
            risk_threshold: Threshold for blocking content (0.0 - 1.0)
            timeout: Request timeout in seconds
            scanners_suppress: List of scanner names to suppress
            fail_on_error: If True, block request on API errors; if False, allow through
            use_scan_endpoint: If True, use /scan/prompt (faster, no sanitization);
                              if False, use /analyze/prompt
            **kwargs: Additional arguments passed to CustomGuardrail
        """
        self.api_key = api_key or os.getenv("LLM_GUARD_API_KEY")
        self.api_base = api_base or os.getenv(
            "LLM_GUARD_API_BASE", "http://localhost:8000"
        )
        self.risk_threshold = risk_threshold
        self.timeout = timeout
        self.scanners_suppress = scanners_suppress or []
        self.fail_on_error = fail_on_error
        self.use_scan_endpoint = use_scan_endpoint
        
        self.optional_params = kwargs
        
        super().__init__(**kwargs)
        
        endpoint = "/scan/prompt" if use_scan_endpoint else "/analyze/prompt"
        verbose_proxy_logger.debug(
            f"LLMGuardDuringCallGuardrail initialized: api_base={self.api_base}, "
            f"endpoint={endpoint}, risk_threshold={self.risk_threshold}"
        )

    def _get_headers(self) -> Dict[str, str]:
        """Get headers for API requests."""
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        return headers

    async def _scan_prompt(self, prompt: str) -> Dict[str, Any]:
        """
        Scan input prompt using LLM Guard API.
        
        Uses /scan/prompt for faster scanning (no sanitization)
        or /analyze/prompt for full analysis.
        """
        async_client = get_async_httpx_client(
            llm_provider=httpxSpecialProvider.LoggingCallback
        )
        
        payload = {"prompt": prompt}
        if self.scanners_suppress:
            payload["scanners_suppress"] = self.scanners_suppress
        
        endpoint = "/scan/prompt" if self.use_scan_endpoint else "/analyze/prompt"
        
        verbose_proxy_logger.debug(
            f"[DuringCall] Scanning prompt: {self.api_base}{endpoint}"
        )
        
        response = await async_client.post(
            f"{self.api_base}{endpoint}",
            headers=self._get_headers(),
            json=payload,
            timeout=self.timeout,
        )
        
        response.raise_for_status()
        return response.json()

    def _extract_messages_text(self, data: dict) -> str:
        """Extract text content from messages in request data."""
        messages = data.get("messages", [])
        text_parts = []
        
        for message in messages:
            content = message.get("content")
            if isinstance(content, str):
                text_parts.append(content)
            elif isinstance(content, list):
                for part in content:
                    if isinstance(part, dict) and part.get("type") == "text":
                        text_parts.append(part.get("text", ""))
        
        return "\n".join(text_parts)

    def _check_scan_result(self, result: Dict[str, Any]) -> None:
        """Check scan result and raise exception if content should be blocked."""
        is_valid = result.get("is_valid", True)
        scanners = result.get("scanners", {})
        
        if not is_valid:
            triggered_scanners = [
                f"{scanner}({score:.2f})" 
                for scanner, score in scanners.items() 
                if score > self.risk_threshold
            ]
            raise ValueError(
                f"[DuringCall] Input blocked by LLM Guard. "
                f"Triggered: {', '.join(triggered_scanners)}"
            )
        
        for scanner, score in scanners.items():
            if score > self.risk_threshold:
                raise ValueError(
                    f"[DuringCall] Input blocked by {scanner}. "
                    f"Score: {score:.2f} (threshold: {self.risk_threshold})"
                )

    async def async_moderation_hook(
        self,
        data: dict,
        user_api_key_dict: UserAPIKeyAuth,
        call_type: Literal[
            "completion",
            "embeddings",
            "image_generation",
            "moderation",
            "audio_transcription",
        ],
    ):
        """
        Moderation hook: Scan input in parallel with LLM API call.
        
        This method runs concurrently with the LLM call for lower latency.
        It can only reject requests, not modify input.
        
        Key differences from pre_call:
        - Runs in PARALLEL with LLM call (lower latency)
        - CANNOT modify input data
        - Only used to ACCEPT or REJECT requests
        
        Args:
            data: Request data containing messages
            user_api_key_dict: User API key information
            call_type: Type of LLM call
        """
        verbose_proxy_logger.debug(
            f"[DuringCall] async_moderation_hook triggered for {call_type}"
        )
        
        prompt_text = self._extract_messages_text(data)
        
        if not prompt_text.strip():
            verbose_proxy_logger.debug("[DuringCall] No text content to scan")
            return
        
        try:
            result = await self._scan_prompt(prompt_text)
            
            verbose_proxy_logger.info(
                f"[DuringCall] Scan result: is_valid={result.get('is_valid')}, "
                f"scanners={result.get('scanners')}"
            )
            
            # Check if content should be blocked
            self._check_scan_result(result)
            
        except ValueError:
            # Re-raise validation errors (blocked content)
            raise
        except Exception as e:
            verbose_proxy_logger.error(f"[DuringCall] LLM Guard API error: {str(e)}")
            if self.fail_on_error:
                raise ValueError(f"[DuringCall] LLM Guard API error: {str(e)}")
            else:
                verbose_proxy_logger.warning(
                    "[DuringCall] Allowing request despite API error"
                )
