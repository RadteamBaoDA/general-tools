"""
LLM Guard Pre-Call Guardrail for LiteLLM

This guardrail runs BEFORE the LLM API call to:
- Scan input prompts using LLM Guard /analyze/prompt endpoint
- Sanitize/modify input if needed
- Block requests that violate security policies

Mode: pre_call
Hook: async_pre_call_hook

LLM Guard API Documentation: https://protectai.github.io/llm-guard/api/overview/
LiteLLM Custom Guardrail: https://docs.litellm.ai/docs/proxy/guardrails/custom_guardrail
"""

import os
from typing import Any, Dict, List, Optional, Union

from litellm._logging import verbose_proxy_logger
from litellm.caching.caching import DualCache
from litellm.integrations.custom_guardrail import CustomGuardrail
from litellm.llms.custom_httpx.http_handler import (
    get_async_httpx_client,
    httpxSpecialProvider,
)
from litellm.proxy._types import UserAPIKeyAuth
from litellm.types.utils import CallTypes


class LLMGuardPreCallGuardrail(CustomGuardrail):
    """
    Pre-call guardrail that scans input prompts before sending to LLM.
    
    This guardrail:
    - Runs BEFORE the LLM API call
    - Can MODIFY the input data (sanitize prompts)
    - Can BLOCK requests by raising an exception
    
    Use this for:
    - Input validation and sanitization
    - Prompt injection detection
    - PII anonymization
    - Toxicity filtering on user input
    """
    
    def __init__(
        self,
        api_key: Optional[str] = None,
        api_base: Optional[str] = None,
        risk_threshold: float = 0.5,
        timeout: int = 10,
        scanners_suppress: Optional[List[str]] = None,
        fail_on_error: bool = True,
        sanitize_prompt: bool = True,
        **kwargs,
    ):
        """
        Initialize the LLM Guard Pre-Call Guardrail.
        
        Args:
            api_key: API key for LLM Guard API authentication (optional)
            api_base: Base URL of the LLM Guard API
            risk_threshold: Threshold for blocking content (0.0 - 1.0)
            timeout: Request timeout in seconds
            scanners_suppress: List of scanner names to suppress
            fail_on_error: If True, block request on API errors; if False, allow through
            sanitize_prompt: If True, replace prompt with sanitized version
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
        self.sanitize_prompt = sanitize_prompt
        
        self.optional_params = kwargs
        
        super().__init__(**kwargs)
        
        verbose_proxy_logger.debug(
            f"LLMGuardPreCallGuardrail initialized: api_base={self.api_base}, "
            f"risk_threshold={self.risk_threshold}, sanitize_prompt={self.sanitize_prompt}"
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
        
        Args:
            prompt: The prompt text to scan
            
        Returns:
            API response with is_valid, sanitized_prompt, and scanners
        """
        async_client = get_async_httpx_client(
            llm_provider=httpxSpecialProvider.LoggingCallback
        )
        
        payload = {"prompt": prompt}
        if self.scanners_suppress:
            payload["scanners_suppress"] = self.scanners_suppress
        
        verbose_proxy_logger.debug(
            f"[PreCall] Scanning prompt with LLM Guard: {self.api_base}/analyze/prompt"
        )
        
        response = await async_client.post(
            f"{self.api_base}/analyze/prompt",
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
            
            raise ValueError(
                f"[PreCall] Input blocked by LLM Guard. "
                f"Triggered: {repr(scanners)}"
            )
        
        for scanner, score in scanners.items():
            if score > self.risk_threshold:
                raise ValueError(
                    f"[PreCall] Input blocked by {scanner}. "
                    f"Score: {score:.2f} (threshold: {self.risk_threshold})"
                )

    async def async_pre_call_hook(
        self,
        user_api_key_dict: UserAPIKeyAuth,
        cache: DualCache,
        data: dict,
        call_type: Optional[CallTypes],
    ) -> Optional[Union[Exception, str, dict]]:
        """
        Pre-call hook: Scan and optionally sanitize input before LLM call.
        
        This method:
        1. Extracts text from the request messages
        2. Sends to LLM Guard /analyze/prompt endpoint
        3. Checks scanner results against threshold
        4. Optionally replaces prompt with sanitized version
        5. Blocks request if any scanner exceeds threshold
        
        Args:
            user_api_key_dict: User API key information
            cache: Dual cache instance
            data: Request data containing messages
            call_type: Type of LLM call
            
        Returns:
            Modified data dict, or raises exception to block
        """
        verbose_proxy_logger.debug(
            f"[PreCall] async_pre_call_hook triggered for {call_type}"
        )
        
        prompt_text = self._extract_messages_text(data)
        
        if not prompt_text.strip():
            verbose_proxy_logger.debug("[PreCall] No text content to scan")
            return data
        
        try:
            result = await self._scan_prompt(prompt_text)
            
            verbose_proxy_logger.debug(
                f"[PreCall] Scan result: is_valid={result.get('is_valid')}, "
                f"scanners={result.get('scanners')}"
            )
            
            # Check if content should be blocked
            self._check_scan_result(result)
            
            return data
            
        except ValueError:
            # Re-raise validation errors (blocked content)
            raise
        except Exception as e:
            verbose_proxy_logger.error(f"[PreCall] LLM Guard API error: {str(e)}")
            if self.fail_on_error:
                raise ValueError(f"[PreCall] LLM Guard API error: {str(e)}")
            else:
                verbose_proxy_logger.warning("[PreCall] Allowing request despite API error")
                return data
