# agent/llm_select.py
import os
from llm_openai_tools import summarize_findings as summarize_openai_tools
from llm_ollama import summarize_findings as summarize_ollama

MODE = os.getenv("LLM_MODE", "openai").lower()

def summarize(findings):
    if MODE == "openai":
        print("[DEBUG] Using OpenAI+tools summarizer")
        return summarize_openai_tools(findings)
    else:
        print("[DEBUG] Using Ollama summarizer")
        return summarize_ollama(findings)
