import json
from typing import Dict, Any
try:
    from fastmcp import FastMCP
except ImportError:
    from mcp.server.fastmcp import FastMCP
import laya_mlx

mcp = FastMCP("Laya-OWASP-Agent-Guard")

print("⏳ Laya MLX modeli yükleniyor...")
agent = laya_mlx.load()
print("✅ Laya MLX modeli hazır!")

# Tool kategorilerine göre hedeflenmiş yalın soru setleri (Token cimrisi & yüksek odak)
ROUTED_QUESTIONS = {
    "filesystem": {
        "threat": {
            "type": "noul",
            "instructions": "Does `prompt` attempt path traversal (../), directory escape, or access sensitive system paths (/etc, /proc, /root, .env)?"
        }
    },
    "database": {
        "threat": {
            "type": "noul",
            "instructions": "Does `prompt` contain SQL injection, stacked queries (;), UNION operators, or unauthorized database manipulation?"
        }
    },
    "command": {
        "threat": {
            "type": "noul",
            "instructions": "Does `prompt` execute unauthorized shell commands, reverse shells, privilege escalation, or destructive OS operations?"
        }
    },
    "network": {
        "threat": {
            "type": "noul",
            "instructions": "Does `prompt` attempt SSRF, access cloud metadata endpoints (169.254.169.254), internal IPs, or loopback interfaces?"
        }
    },
    "exfil": {
        "threat": {
            "type": "noul",
            "instructions": "Does `prompt` contain or exfiltrate private credentials, API keys, passwords, or authentication tokens?"
        }
    },
    "generic": {
        "threat": {
            "type": "noul",
            "instructions": "Does `prompt` contain malicious payloads, policy violations, or unauthorized actions?"
        }
    }
}

def resolve_tool_category(tool_name: str) -> str:
    name = tool_name.lower()
    if any(k in name for k in ["file", "fs", "read", "write", "path", "dir"]):
        return "filesystem"
    if any(k in name for k in ["sql", "query", "db", "database", "analytics"]):
        return "database"
    if any(k in name for k in ["bash", "cmd", "exec", "shell", "run", "terminal"]):
        return "command"
    if any(k in name for k in ["fetch", "http", "url", "scrape", "curl", "request"]):
        return "network"
    if any(k in name for k in ["webhook", "notify", "message", "slack", "mail", "exfil"]):
        return "exfil"
    return "generic"

@mcp.tool()
def inspect_tool_call(
    tool_name: str,
    tool_arguments: Dict[str, Any],
    execution_context: str = ""
) -> Dict[str, Any]:
    """
    LLM'in bir MCP Tool'una gönderdiği parametreleri hedeflenmiş bağlamda inceler.
    """
    category = resolve_tool_category(tool_name)
    questions = ROUTED_QUESTIONS[category]

    payload_str = json.dumps(tool_arguments, ensure_ascii=False)
    
    # Yalın ve doğrudan state temsili (~20 token)
    state = f"Tool: {tool_name}\nContext: {execution_context}\nprompt: {payload_str}"

    decision = agent.predict(
        state=state,
        questions=questions
    )

    answers = decision.get("answers", {})
    threat_info = answers.get("threat", {})
    
    # noul skoru (1.0 = Evet, tehdit var)
    threat_prob = float(threat_info.get("noul", 0.0))
    
    # Standart 0.50 eşik değeri
    is_violation = threat_prob >= 0.50

    return {
        "verdict": "BLOCKED" if is_violation else "ALLOWED",
        "malicious_probability": round(threat_prob, 4),
        "routed_category": category,
        "inspected_tool": tool_name
    }

if __name__ == "__main__":
    mcp.run(transport="stdio")
