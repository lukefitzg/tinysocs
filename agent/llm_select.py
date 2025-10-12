import os
from llm_ollama import summarize_findings as summarize_ollama
from llm_openai import summarize_findings as summarize_openai
from llm_openai_tools import summarize_findings as summarize_openai_tools

def summarize(findings):
    mode = os.getenv("LLM_MODE", "ollama").lower()
    if mode == "openai_tools":
        print("[DEBUG] Using OpenAI+tools summarizer")
        return summarize_openai_tools(findings)
    if mode == "openai":
        print("[DEBUG] Using OpenAI summarizer")
        return summarize_openai(findings)
    print("[DEBUG] Using Ollama summarizer")
    return summarize_ollama(findings)
