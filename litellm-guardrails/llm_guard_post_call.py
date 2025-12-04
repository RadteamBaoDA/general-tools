"""
LLM Guard Post-Call Guardrail for LiteLLM

This guardrail runs AFTER the LLM API call to:
- Scan LLM output using LLM Guard /analyze/output endpoint
- Handle both streaming and non-streaming responses
- Block responses that violate security policies

Mode: post_call
Hooks: 
  - async_post_call_success_hook (non-streaming)
  - async_post_call_streaming_iterator_hook (streaming)

LLM Guard API Documentation: https://protectai.github.io/llm-guard/api/overview/
LiteLLM Custom Guardrail: https://docs.litellm.ai/docs/proxy/guardrails/custom_guardrail
"""

import os
import asyncio
from typing import Any, AsyncGenerator, Dict, List, Optional

import litellm
from litellm._logging import verbose_proxy_logger
from litellm.integrations.custom_guardrail import CustomGuardrail
from litellm.llms.custom_httpx.http_handler import (
    get_async_httpx_client,
    httpxSpecialProvider,
)
from litellm.proxy._types import UserAPIKeyAuth
from litellm.types.utils import ModelResponseStream
from litellm.proxy.proxy_server import StreamingCallbackError


class LLMGuardPostCallGuardrail(CustomGuardrail):
    """
    Post-call guardrail that scans LLM output after the response.
    
    This guardrail:
    - Runs AFTER the LLM API call completes
    - Scans the complete output (non-streaming)
    - Scans streaming chunks periodically (streaming)
    - Can BLOCK responses by raising an exception
    
    Use this for:
    - Output content validation
    - PII detection in responses
    - Toxicity filtering on LLM output
    - Bias detection
    - Factual consistency checking
    """
    
    def __init__(
        self,
        api_key: Optional[str] = None,
        api_base: Optional[str] = None,
        risk_threshold: float = 0.5,
        timeout: int = 30,
        scanners_suppress: Optional[List[str]] = None,
        fail_on_error: bool = True,
        stream_scan_interval: int = 100,
        scan_partial_stream: bool = True,
        **kwargs,
    ):
        """
        Initialize the LLM Guard Post-Call Guardrail.
        
        Args:
            api_key: API key for LLM Guard API authentication (optional)
            api_base: Base URL of the LLM Guard API
            risk_threshold: Threshold for blocking content (0.0 - 1.0)
            timeout: Request timeout in seconds (longer for output scanning)
            scanners_suppress: List of scanner names to suppress
            fail_on_error: If True, block response on API errors; if False, allow through
            stream_scan_interval: Number of characters between stream scans
            scan_partial_stream: If True, scan during streaming; if False, only scan at end
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
        self.stream_scan_interval = stream_scan_interval
        self.scan_partial_stream = scan_partial_stream
        
        self.optional_params = kwargs
        
        super().__init__(**kwargs)
        
        verbose_proxy_logger.debug(
            f"LLMGuardPostCallGuardrail initialized: api_base={self.api_base}, "
            f"risk_threshold={self.risk_threshold}, stream_interval={stream_scan_interval}"
        )

    def _get_headers(self) -> Dict[str, str]:
        """Get headers for API requests."""
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        return headers

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
            f"[PostCall] Scanning output: {self.api_base}/analyze/output"
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

    def _extract_response_text(self, response) -> str:
        """Extract text content from LLM response."""
        output_text = ""
        if isinstance(response, litellm.ModelResponse):
            for choice in response.choices:
                if isinstance(choice, litellm.Choices):
                    if choice.message and choice.message.content:
                        if isinstance(choice.message.content, str):
                            output_text += choice.message.content
        return output_text

    def _check_scan_result(self, result: Dict[str, Any], context: str = "") -> None:
        """Check scan result and raise exception if content should be blocked."""
        is_valid = result.get("is_valid", True)
        scanners = result.get("scanners", {})
        
        ctx = f"[PostCall{context}]"
        
        if not is_valid:
            raise ValueError(
                f"{ctx} Output blocked by LLM Guard. "
                f"Triggered: {repr(scanners)}"
            )
        
        for scanner, score in scanners.items():
            if score > self.risk_threshold:
                raise ValueError(
                    f"{ctx} Output blocked by {scanner}. "
                    f"Score: {score:.2f} (threshold: {self.risk_threshold})"
                )


    async def _read_stream_to_queue(
        self, response: Any, queue: asyncio.Queue
    ) -> None:
        """
        Producer task: Read chunks from response stream and put into queue.
        """
        try:
            async for chunk in response:
                await queue.put(chunk)
        except Exception as e:
            verbose_proxy_logger.error(f"[PostCall-Stream] Error reading stream: {str(e)}")
        finally:
            await queue.put(None)  # Sentinel for end of stream

    async def async_post_call_streaming_iterator_hook(
        self,
        user_api_key_dict: UserAPIKeyAuth,
        response: Any,
        request_data: dict,
    ) -> AsyncGenerator[ModelResponseStream, None]:
        """
        Streaming iterator hook: Scan streaming output chunks.
        
        This method processes streaming responses and can:
        - Scan accumulated content periodically
        - Block the stream if content is flagged
        - Perform final scan when stream completes
        
        Note: This hook is called when stream=True
        
        Args:
            user_api_key_dict: User API key information
            response: Async generator of stream chunks
            request_data: Original request data
            
        Yields:
            ModelResponseStream chunks
        """
        verbose_proxy_logger.debug(
            "[PostCall] async_post_call_streaming_iterator_hook triggered"
        )
        
        # Extract original prompt
        prompt_text = self._extract_messages_text(request_data)
        
        # Buffer for chunks and accumulated text
        chunk_buffer: List[ModelResponseStream] = []
        accumulated_output = ""
        last_scan_length = 0
        
        # Create queue and start producer task
        queue = asyncio.Queue()
        producer_task = asyncio.create_task(self._read_stream_to_queue(response, queue))
        
        try:
            while True:
                # Get chunk from queue
                chunk = await queue.get()
                
                if chunk is None:  # End of stream
                    break
                
                # Buffer the chunk
                chunk_buffer.append(chunk)
                
                # Extract text from chunk
                if isinstance(chunk, ModelResponseStream):
                    for choice in chunk.choices:
                        if hasattr(choice, "delta") and choice.delta:
                            if hasattr(choice.delta, "content") and choice.delta.content:
                                accumulated_output += choice.delta.content
                
                # Periodically scan accumulated content (if enabled)
                if self.scan_partial_stream:
                    if len(accumulated_output) - last_scan_length >= self.stream_scan_interval:
                        try:
                            result = await self._scan_output(prompt_text, accumulated_output)
                            
                            verbose_proxy_logger.debug(
                                f"[PostCall-Stream] Partial scan: is_valid={result.get('is_valid')}, "
                                f"length={len(accumulated_output)}"
                            )
                            
                            self._check_scan_result(result, "-Stream")
                            
                            # If valid, yield all buffered chunks
                            for buffered_chunk in chunk_buffer:
                                yield buffered_chunk
                            chunk_buffer = [] # Clear buffer
                            
                            last_scan_length = len(accumulated_output)
                            
                        except ValueError as e:
                            # Block the stream
                            raise StreamingCallbackError(
                                message=str(e),
                                llm_provider="llm_guard"
                            )
                        except Exception as e:
                            verbose_proxy_logger.error(
                                f"[PostCall-Stream] Partial scan error: {str(e)}"
                            )
                            if self.fail_on_error:
                                raise StreamingCallbackError(
                                    message=f"[PostCall-Stream] LLM Guard API error: {str(e)}",
                                    llm_provider="llm_guard"
                                )
                            else:
                                # If we allow on error, yield buffered chunks
                                for buffered_chunk in chunk_buffer:
                                    yield buffered_chunk
                                chunk_buffer = []
                else:
                     # If partial scan is disabled, just yield immediately (no buffering)
                     yield chunk
                     chunk_buffer = [] # Ensure buffer stays empty
            
            # Final scan of complete output
            if accumulated_output and len(accumulated_output) > last_scan_length:
                try:
                    result = await self._scan_output(prompt_text, accumulated_output)
                    
                    verbose_proxy_logger.info(
                        f"[PostCall-Stream] Final scan: is_valid={result.get('is_valid')}, "
                        f"scanners={result.get('scanners')}"
                    )
                    
                    self._check_scan_result(result, "-StreamFinal")
                    
                    # Yield any remaining buffered chunks
                    for buffered_chunk in chunk_buffer:
                        yield buffered_chunk
                    
                except ValueError as e:
                    raise StreamingCallbackError(
                        message=str(e),
                        llm_provider="llm_guard"
                    )
                except Exception as e:
                    verbose_proxy_logger.error(
                        f"[PostCall-Stream] Final scan error: {str(e)}"
                    )
                    if self.fail_on_error:
                        raise StreamingCallbackError(
                            message=f"[PostCall-Stream] LLM Guard API error: {str(e)}",
                            llm_provider="llm_guard"
                        )
                    else:
                        for buffered_chunk in chunk_buffer:
                            yield buffered_chunk
                            
        finally:
            # Ensure producer task is cancelled if we exit early
            if not producer_task.done():
                producer_task.cancel()
                try:
                    await producer_task
                except asyncio.CancelledError:
                    pass
