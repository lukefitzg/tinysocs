SCHEMA = {
  "type": "object",
  "properties": {
    "tldr": {"type": "string"},
    "severity": {"type": "string", "enum": ["Low","Medium","High"]},
    "evidence": {"type": "array", "items": {"type": "object"}},
    "hypotheses": {"type": "array", "items": {"type": "string"}},
    "next_steps": {"type": "array", "items": {"type": "string"}},
    "candidate_actions": {"type": "array", "items": {"type": "object"}}
  },
  "required": ["tldr","severity","evidence","next_steps"]
}
