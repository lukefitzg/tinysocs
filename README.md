# TinySocs

Local, self-powered SIEM assistant. Wraps Elastic/OpenSearch and uses an LLM (OpenAI or local via Ollama) to query, analyze, and summarize security events.

## Setup (Windows)
1. Clone the repo
2. Create a Python venv: `python -m venv .venv && source .venv/Scripts/activate`
3. Install deps: `pip install -r requirements.txt`
4. Copy `.env.example` to `.env` and fill values
5. Run: `python agent/main.py`

## Env toggles
- `LLM_MODE=openai` (cloud) or `LLM_MODE=ollama` (local)
- `SIEM_BACKEND=elastic | opensearch`
