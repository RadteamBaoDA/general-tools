"""
Custom LiteLLM Guardrail using LLM Guard API

This guardrail integrates with a self-hosted LLM Guard API to scan:
- Input prompts (pre_call) using /analyze/prompt endpoint
- Streaming output (during_call) using /analyze/output endpoint
- Non-streaming output (post_call) using /analyze/output endpoint

LLM Guard API Documentation: https://protectai.github.io/llm-guard/api/overview/
LiteLLM Custom Guardrail: https://docs.litellm.ai/docs/proxy/guardrails/custom_guardrail
"""

import os
from typing import Any, AsyncGenerator, Dict, List, Literal, Optional, Union

import litellm
from litellm._logging import verbose_proxy_logger
from litellm.caching.caching import DualCache
from litellm.integrations.custom_guardrail import CustomGuardrail
from litellm.llms.custom_httpx.http_handler import (
    get_async_httpx_client,
    httpxSpecialProvider,
)
from litellm.proxy._types import UserAPIKeyAuth
from litellm.types.utils import ModelResponseStream, CallTypes


class LLMGuardGuardrail(CustomGuardrail):
    """
    Custom guardrail that integrates with LLM Guard API for content scanning.
    
    Supports:
    - pre_call: Scans input prompts before sending to LLM
    - during_call: Scans streaming output chunks
    - post_call: Scans complete output after LLM response
    """
    
    def __init__(
        self,
        api_key: Optional[str] = None,
        api_base: Optional[str] = None,
        risk_threshold: float = 0.5,
        timeout: int = 10,
        scanners_suppress: Optional[List[str]] = None,
        **kwargs,
    ):
        """
        Initialize the LLM Guard Guardrail.
        
        Args:
            api_key: API key for LLM Guard API authentication (optional)
            api_base: Base URL of the LLM Guard API
            risk_threshold: Threshold for blocking content (0.0 - 1.0)
            timeout: Request timeout in seconds
            scanners_suppress: List of scanner names to suppress
            **kwargs: Additional arguments passed to CustomGuardrail
        """
        self.api_key = api_key or os.getenv("LLM_GUARD_API_KEY")
        self.api_base = api_base or os.getenv(
            "LLM_GUARD_API_BASE", "http://localhost:8000"
        )
        self.risk_threshold = risk_threshold
        self.timeout = timeout
        self.scanners_suppress = scanners_suppress or []
        
        # Store kwargs as optional_params
        self.optional_params = kwargs
        
        super().__init__(**kwargs)
        
        verbose_proxy_logger.debug(
            f"LLMGuardGuardrail initialized with api_base={self.api_base}, "
            f"risk_threshold={self.risk_threshold}"
        )

    def _get_headers(self) -> Dict[str, str]:
        """Get headers for API requests."""
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        return headers

    def _check_scan_result(
        self, result: Dict[str, Any], scan_type: str
    ) -> None:
        """
        Check scan result and raise exception if content should be blocked.
        
        Args:
            result: API response containing is_valid and scanners fields
            scan_type: Type of scan (input/output) for error messages
        """
        is_valid = result.get("is_valid", True)
        scanners = result.get("scanners", {})
        
        if not is_valid:
            # Find scanners that triggered the block
            triggered_scanners = [
                scanner for scanner, score in scanners.items() 
                if score > self.risk_threshold
            ]
            raise ValueError(
                f"LLM Guard {scan_type} scan failed. "
                f"Triggered scanners: {', '.join(triggered_scanners)}. "
                f"Scores: {scanners}"
            )
        
        # Also check individual scanner scores against threshold
        for scanner, score in scanners.items():
            if score > self.risk_threshold:
                raise ValueError(
                    f"LLM Guard {scan_type} scan blocked by {scanner}. "
                    f"Risk score: {score} (threshold: {self.risk_threshold})"
                )

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
            f"Scanning prompt with LLM Guard API: {self.api_base}/analyze/prompt"
        )
        
        response = await async_client.post(
            f"{self.api_base}/analyze/prompt",
            headers=self._get_headers(),
            json=payload,
            timeout=self.timeout,
        )
        
        response.raise_for_status()
        return response.json()

    async def _scan_output(self, prompt: str, output: str) -> Dict[str, Any]:
        """
        Scan output using LLM Guard API.
        
        Args:
            prompt: The original prompt
            output: The LLM output to scan
            
        Returns:
            API response with is_valid, sanitized_output, and scanners
        """
        async_client = get_async_httpx_client(
            llm_provider=httpxSpecialProvider.LoggingCallback
        )
        
        payload = {
            "prompt": prompt,
            "output": output,
        }
        if self.scanners_suppress:
            payload["scanners_suppress"] = self.scanners_suppress
        
        verbose_proxy_logger.debug(
            f"Scanning output with LLM Guard API: {self.api_base}/analyze/output"
        )
        
        response = await async_client.post(
            f"{self.api_base}/analyze/output",
            headers=self._get_headers(),
            json=payload,
            timeout=self.timeout,
        )
        
        response.raise_for_status()
        return response.json()

    def _extract_messages_text(self, data: dict) -> str:
        """
        Extract text content from messages in request data.
        
        Args:
            data: Request data containing messages
            
        Returns:
            Combined text from all messages
        """
        messages = data.get("messages", [])
        text_parts = []
        
        for message in messages:
            content = message.get("content")
            if isinstance(content, str):
                text_parts.append(content)
            elif isinstance(content, list):
                # Handle multimodal content
                for part in content:
                    if isinstance(part, dict) and part.get("type") == "text":
                        text_parts.append(part.get("text", ""))
        
        return "\n".join(text_parts)

    async def async_pre_call_hook(
        self,
        user_api_key_dict: UserAPIKeyAuth,
        cache: DualCache,
        data: dict,
        call_type: Optional[CallTypes],
    ) -> Optional[Union[Exception, str, dict]]:
        """
        Pre-call hook: Scan input prompts before sending to LLM.
        
        This hook runs BEFORE the LLM API call and can:
        - Modify the input data
        - Reject the request by raising an exception
        
        Triggered by mode: 'pre_call'
        
        Args:
            user_api_key_dict: User API key information
            cache: Dual cache instance
            data: Request data containing messages
            call_type: Type of LLM call
            
        Returns:
            Modified data dict or raises exception to block
        """
        verbose_proxy_logger.debug(
            f"LLMGuardGuardrail async_pre_call_hook called for {call_type}"
        )
        
        # Extract text from messages
        prompt_text = self._extract_messages_text(data)
        
        if not prompt_text.strip():
            verbose_proxy_logger.debug("No text content to scan in pre_call")
            return data
        
        try:
            result = await self._scan_prompt(prompt_text)
            
            verbose_proxy_logger.debug(
                f"LLM Guard prompt scan result: is_valid={result.get('is_valid')}, "
                f"scanners={result.get('scanners')}"
            )
            
            # Check if content should be blocked
            self._check_scan_result(result, "input")
            
            # Optionally update messages with sanitized prompt if available
            sanitized_prompt = result.get("sanitized_prompt")
            if sanitized_prompt and sanitized_prompt != prompt_text:
                verbose_proxy_logger.debug(
                    "Prompt was sanitized by LLM Guard"
                )
                # Update the last user message with sanitized content
                messages = data.get("messages", [])
                for message in reversed(messages):
                    if message.get("role") == "user":
                        message["content"] = sanitized_prompt
                        break
            
            return data
            
        except Exception as e:
            verbose_proxy_logger.error(f"LLM Guard pre_call scan error: {str(e)}")
            raise

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
        Moderation hook: Runs in parallel with LLM API call.
        
        This hook runs DURING the LLM API call in parallel.
        It can only reject requests, not modify input.
        
        Triggered by mode: 'during_call'
        
        Args:
            data: Request data
            user_api_key_dict: User API key information
            call_type: Type of LLM call
        """
        verbose_proxy_logger.debug(
            f"LLMGuardGuardrail async_moderation_hook called for {call_type}"
        )
        
        # Extract text from messages
        prompt_text = self._extract_messages_text(data)
        
        if not prompt_text.strip():
            verbose_proxy_logger.debug("No text content to scan in moderation_hook")
            return
        
        try:
            result = await self._scan_prompt(prompt_text)
            
            verbose_proxy_logger.debug(
                f"LLM Guard moderation scan result: is_valid={result.get('is_valid')}, "
                f"scanners={result.get('scanners')}"
            )
            
            # Check if content should be blocked
            self._check_scan_result(result, "input")
            
        except Exception as e:
            verbose_proxy_logger.error(f"LLM Guard moderation scan error: {str(e)}")
            raise

    async def async_post_call_success_hook(
        self,
        data: dict,
        user_api_key_dict: UserAPIKeyAuth,
        response,
    ):
        """
        Post-call success hook: Scan output after LLM response (non-streaming).
        
        This hook runs AFTER the LLM API call completes successfully.
        It can reject responses by raising an exception.
        
        Triggered by mode: 'post_call' when stream=False
        
        Args:
            data: Original request data
            user_api_key_dict: User API key information
            response: LLM response object
        """
        verbose_proxy_logger.debug(
            f"LLMGuardGuardrail async_post_call_success_hook called"
        )
        
        # Extract original prompt
        prompt_text = self._extract_messages_text(data)
        
        # Extract output from response
        output_text = ""
        if isinstance(response, litellm.ModelResponse):
            for choice in response.choices:
                if isinstance(choice, litellm.Choices):
                    if choice.message and choice.message.content:
                        if isinstance(choice.message.content, str):
                            output_text += choice.message.content
        
        if not output_text.strip():
            verbose_proxy_logger.debug("No output content to scan in post_call")
            return
        
        try:
            result = await self._scan_output(prompt_text, output_text)
            
            verbose_proxy_logger.debug(
                f"LLM Guard output scan result: is_valid={result.get('is_valid')}, "
                f"scanners={result.get('scanners')}"
            )
            
            # Check if content should be blocked
            self._check_scan_result(result, "output")
            
        except Exception as e:
            verbose_proxy_logger.error(f"LLM Guard post_call scan error: {str(e)}")
            raise

    async def async_post_call_streaming_iterator_hook(
        self,
        user_api_key_dict: UserAPIKeyAuth,
        response: Any,
        request_data: dict,
    ) -> AsyncGenerator[ModelResponseStream, None]:
        """
        Streaming iterator hook: Scan streaming output chunks.
        
        This hook processes streaming responses and can:
        - Scan accumulated content
        - Block the stream if content is flagged
        
        Triggered by mode: 'post_call' when stream=True
        
        Args:
            user_api_key_dict: User API key information
            response: Async generator of stream chunks
            request_data: Original request data
            
        Yields:
            ModelResponseStream chunks
        """
        verbose_proxy_logger.debug(
            "LLMGuardGuardrail async_post_call_streaming_iterator_hook called"
        )
        
        # Extract original prompt
        prompt_text = self._extract_messages_text(request_data)
        
        # Accumulate stream content for scanning
        accumulated_output = ""
        scan_interval = 100  # Scan every N characters
        last_scan_length = 0
        
        async for chunk in response:
            # Extract text from chunk
            if isinstance(chunk, ModelResponseStream):
                for choice in chunk.choices:
                    if hasattr(choice, "delta") and choice.delta:
                        if hasattr(choice.delta, "content") and choice.delta.content:
                            accumulated_output += choice.delta.content
            
            # Periodically scan accumulated content
            if len(accumulated_output) - last_scan_length >= scan_interval:
                try:
                    result = await self._scan_output(prompt_text, accumulated_output)
                    
                    verbose_proxy_logger.debug(
                        f"LLM Guard stream scan result: is_valid={result.get('is_valid')}, "
                        f"length={len(accumulated_output)}"
                    )
                    
                    # Check if content should be blocked
                    self._check_scan_result(result, "output (streaming)")
                    
                    last_scan_length = len(accumulated_output)
                    
                except Exception as e:
                    verbose_proxy_logger.error(
                        f"LLM Guard streaming scan error: {str(e)}"
                    )
                    raise
            
            yield chunk
        
        # Final scan of complete output
        if accumulated_output and len(accumulated_output) > last_scan_length:
            try:
                result = await self._scan_output(prompt_text, accumulated_output)
                
                verbose_proxy_logger.debug(
                    f"LLM Guard final stream scan result: is_valid={result.get('is_valid')}"
                )
                
                self._check_scan_result(result, "output (streaming final)")
                
            except Exception as e:
                verbose_proxy_logger.error(
                    f"LLM Guard final streaming scan error: {str(e)}"
                )
                raise
