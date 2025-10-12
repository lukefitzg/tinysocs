# Create Model Toggles in PowerShell session
function Use-OpenAI {
  $env:LLM_MODE = "openai"
  Remove-Item Env:OFFLINE_LLM_URL   -ErrorAction SilentlyContinue
  Remove-Item Env:OFFLINE_LLM_MODEL -ErrorAction SilentlyContinue
  Write-Host "[TinySocs] Using OpenAI (cloud) mode."
}

function Use-Ollama {
  param(
    [string]$Url   = "http://localhost:11434",
    [string]$Model = "qwen2.5:0.5b-instruct"
  )
  $env:LLM_MODE = "ollama"
  $env:OFFLINE_LLM_URL   = $Url
  $env:OFFLINE_LLM_MODEL = $Model
  Write-Host "[TinySocs] Using Ollama (local) mode -> $Url ($Model)"
}

# Toggle commands
Use-OpenAI
# or later:
Use-Ollama -Model "qwen2.5:0.5b-instruct"
