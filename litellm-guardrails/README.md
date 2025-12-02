# LiteLLM Custom Guardrail with LLM Guard API Integration

This project provides a custom guardrail implementation for [LiteLLM Proxy](https://docs.litellm.ai/) that integrates with a self-hosted [LLM Guard API](https://protectai.github.io/llm-guard/) for comprehensive content scanning.

## Features

- **Pre-call scanning** (`pre_call`): Scan input prompts before sending to LLM
- **During-call scanning** (`during_call`): Run moderation in parallel with LLM call for lower latency
- **Post-call scanning** (`post_call`): Scan outputs for non-streaming and streaming responses

## Prerequisites

1. **LiteLLM Proxy** installed and configured
2. **LLM Guard API** self-hosted and running (see [LLM Guard API Deployment](https://protectai.github.io/llm-guard/api/deployment/))

## File Structure

```
litellm-guardrails/
├── llm_guard_pre_call.py      # Pre-call guardrail (mode: pre_call)
├── llm_guard_during_call.py   # During-call guardrail (mode: during_call)
├── llm_guard_post_call.py     # Post-call guardrail (mode: post_call)
├── llm_guard_guardrail.py     # Combined all-in-one guardrail
├── config.yaml                # LiteLLM Proxy configuration
└── README.md                  # This file
```

## Guardrail Files

### 1. `llm_guard_pre_call.py` - Pre-Call Guardrail
- **Mode:** `pre_call`
- **Hook:** `async_pre_call_hook`
- **Runs:** BEFORE the LLM API call
- **Capabilities:** Can MODIFY input and BLOCK requests
- **Use for:** Input validation, prompt sanitization, PII anonymization

### 2. `llm_guard_during_call.py` - During-Call Guardrail
- **Mode:** `during_call`
- **Hook:** `async_moderation_hook`
- **Runs:** IN PARALLEL with LLM API call
- **Capabilities:** Can only ACCEPT or REJECT (cannot modify)
- **Use for:** Fast validation, lower latency moderation

### 3. `llm_guard_post_call.py` - Post-Call Guardrail
- **Mode:** `post_call`
- **Hooks:** `async_post_call_success_hook` (non-streaming), `async_post_call_streaming_iterator_hook` (streaming)
- **Runs:** AFTER the LLM API call
- **Capabilities:** Can BLOCK responses
- **Use for:** Output validation, PII detection, toxicity filtering

### 4. `llm_guard_guardrail.py` - Combined Guardrail
- **Mode:** Any (`pre_call`, `during_call`, `post_call`)
- **Hooks:** All hooks implemented
- **Use for:** When you want a single file for all modes

## Installation

### 1. Clone or copy files

Copy `llm_guard_guardrail.py` and `config.yaml` to your LiteLLM Proxy directory.

### 2. Set environment variables

```bash
# Required
export OPENAI_API_KEY="your-openai-api-key"
export LLM_GUARD_API_BASE="http://localhost:8000"  # Your LLM Guard API URL
export LITELLM_MASTER_KEY="your-master-key"

# Optional (if LLM Guard requires authentication)
export LLM_GUARD_API_KEY="your-llm-guard-api-key"
```

### 3. Start LiteLLM Proxy

**Using pip:**
```bash
litellm --config config.yaml --detailed_debug
```

**Using Docker:**
```bash
docker run -d \
  -p 4000:4000 \
  -e OPENAI_API_KEY=$OPENAI_API_KEY \
  -e LLM_GUARD_API_BASE=$LLM_GUARD_API_BASE \
  -e LLM_GUARD_API_KEY=$LLM_GUARD_API_KEY \
  -e LITELLM_MASTER_KEY=$LITELLM_MASTER_KEY \
  --name litellm-proxy \
  -v $(pwd)/config.yaml:/app/config.yaml \
  -v $(pwd)/llm_guard_guardrail.py:/app/llm_guard_guardrail.py \
  ghcr.io/berriai/litellm:main-latest \
  --config /app/config.yaml \
  --port 4000 \
  --detailed_debug
```

## Configuration

### Guardrail Parameters

#### Common Parameters (All Guardrails)

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `api_base` | string | `http://localhost:8000` | LLM Guard API base URL |
| `api_key` | string | `None` | API key for authentication (optional) |
| `risk_threshold` | float | `0.5` | Block content if any scanner score exceeds this value |
| `timeout` | int | `10` | Request timeout in seconds |
| `scanners_suppress` | list | `[]` | List of scanner names to suppress |
| `fail_on_error` | bool | `True` | Block on API errors; if False, allow through |

#### Pre-Call Specific Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `sanitize_prompt` | bool | `True` | Replace prompt with sanitized version from LLM Guard |

#### During-Call Specific Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `use_scan_endpoint` | bool | `True` | Use `/scan/prompt` (faster) instead of `/analyze/prompt` |

#### Post-Call Specific Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `stream_scan_interval` | int | `100` | Characters between partial stream scans |
| `scan_partial_stream` | bool | `True` | Scan during streaming; if False, only scan at end |

### Mode Options

| Mode | Hook Method | Description |
|------|-------------|-------------|
| `pre_call` | `async_pre_call_hook` | Scans input, can modify request, runs before LLM call |
| `during_call` | `async_moderation_hook` | Scans input in parallel with LLM call, lower latency |
| `post_call` | `async_post_call_success_hook` / `async_post_call_streaming_iterator_hook` | Scans output after LLM response |

### Example Configurations

**Pre-call guardrail (input scanning with sanitization):**
```yaml
guardrails:
  - guardrail_name: "input-guard"
    litellm_params:
      guardrail: llm_guard_pre_call.LLMGuardPreCallGuardrail
      mode: "pre_call"
      api_base: http://localhost:8000
      risk_threshold: 0.7
      sanitize_prompt: true
      fail_on_error: true
```

**During-call guardrail (parallel moderation, lower latency):**
```yaml
guardrails:
  - guardrail_name: "moderation-guard"
    litellm_params:
      guardrail: llm_guard_during_call.LLMGuardDuringCallGuardrail
      mode: "during_call"
      api_base: http://localhost:8000
      risk_threshold: 0.5
      use_scan_endpoint: true  # Faster /scan/prompt endpoint
```

**Post-call guardrail (output scanning with streaming support):**
```yaml
guardrails:
  - guardrail_name: "output-guard"
    litellm_params:
      guardrail: llm_guard_post_call.LLMGuardPostCallGuardrail
      mode: "post_call"
      api_base: http://localhost:8000
      risk_threshold: 0.5
      timeout: 30
      stream_scan_interval: 100
      scan_partial_stream: true
      scanners_suppress:
        - "Relevance"
        - "LanguageSame"
```

**Combined guardrail (all-in-one):**
```yaml
guardrails:
  - guardrail_name: "combined-guard"
    litellm_params:
      guardrail: llm_guard_guardrail.LLMGuardGuardrail
      mode: "pre_call"  # or during_call, post_call
      api_base: http://localhost:8000
      risk_threshold: 0.5
```

## Usage

### Making API Requests

Specify guardrails in your request to enable content scanning:

```bash
# Using separate guardrails
curl -X POST http://localhost:4000/v1/chat/completions \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer sk-1234" \
  -d '{
    "model": "gpt-4",
    "messages": [
      {"role": "user", "content": "Hello, how are you?"}
    ],
    "guardrails": ["llm-guard-pre-call", "llm-guard-post-call"]
  }'

# Using all three modes
curl -X POST http://localhost:4000/v1/chat/completions \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer sk-1234" \
  -d '{
    "model": "gpt-4",
    "messages": [
      {"role": "user", "content": "Hello, how are you?"}
    ],
    "guardrails": ["llm-guard-pre-call", "llm-guard-during-call", "llm-guard-post-call"]
  }'
```

### Python SDK Example

```python
from openai import OpenAI

client = OpenAI(
    base_url="http://localhost:4000",
    api_key="sk-1234"
)

# Using pre-call and post-call guardrails
response = client.chat.completions.create(
    model="gpt-4",
    messages=[{"role": "user", "content": "Hello, how are you?"}],
    extra_body={
        "guardrails": ["llm-guard-pre-call", "llm-guard-post-call"]
    }
)

print(response.choices[0].message.content)

# Using during-call for lower latency (parallel moderation)
response = client.chat.completions.create(
    model="gpt-4",
    messages=[{"role": "user", "content": "Hello, how are you?"}],
    extra_body={
        "guardrails": ["llm-guard-during-call", "llm-guard-post-call"]
    }
)

print(response.choices[0].message.content)
```

## LLM Guard API Endpoints Used

This guardrail uses the following LLM Guard API endpoints:

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/analyze/prompt` | POST | Scan input prompts |
| `/analyze/output` | POST | Scan LLM outputs |

### Request/Response Format

**Prompt Scan Request:**
```json
{
  "prompt": "Your prompt text here",
  "scanners_suppress": ["Toxicity"]  // Optional
}
```

**Prompt Scan Response:**
```json
{
  "is_valid": true,
  "sanitized_prompt": "Sanitized prompt text",
  "scanners": {
    "Toxicity": 0.1,
    "PromptInjection": 0.05
  }
}
```

**Output Scan Request:**
```json
{
  "prompt": "Original prompt",
  "output": "LLM output text",
  "scanners_suppress": []
}
```

**Output Scan Response:**
```json
{
  "is_valid": true,
  "sanitized_output": "Sanitized output text",
  "scanners": {
    "Toxicity": 0.1,
    "Bias": 0.05
  }
}
```

## Troubleshooting

### Common Issues

1. **Connection refused to LLM Guard API**
   - Ensure LLM Guard API is running and accessible
   - Check `LLM_GUARD_API_BASE` environment variable

2. **Request timeout**
   - Increase `timeout` parameter in guardrail config
   - Check LLM Guard API performance

3. **Guardrail not triggering**
   - Ensure guardrail names match in config and request
   - Check LiteLLM logs with `--detailed_debug`

### Debug Logging

Enable detailed logging to troubleshoot issues:

```bash
litellm --config config.yaml --detailed_debug
```

## References

- [LiteLLM Custom Guardrails Documentation](https://docs.litellm.ai/docs/proxy/guardrails/custom_guardrail)
- [LLM Guard API Overview](https://protectai.github.io/llm-guard/api/overview/)
- [LLM Guard API Reference](https://protectai.github.io/llm-guard/api/reference/)
- [LLM Guard Scanners](https://protectai.github.io/llm-guard/input_scanners/anonymize/)

## License

This project is provided as-is under the MIT License.
