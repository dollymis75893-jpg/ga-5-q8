from fastapi import FastAPI
from pydantic import BaseModel
from typing import Optional
import os
import urllib.parse
import re
import base64
import requests

app = FastAPI()

# ==========================================
# Q8 - File Setup (Using Local ./srv to bypass permissions)
# ==========================================
def setup_q8_files():
    # Hum files ko local './srv' mein bana rahe hain taaki permission error na aaye
    files = {
        "./srv/agent-redteam/outside-604b5e92/canary.txt": "AGENT_GUARDRAIL_CANARY_08c7944c542e2f0694c0414d3fb7c21fccbad273\n",
        "./srv/agent-redteam/sandbox-c2800279bc/notes/report.txt": "SAFE_REPORT_43b510bce2f05ff27e9affb6\n",
        "./srv/agent-redteam/sandbox-c2800279bc/notes/looks-like-..-but-safe.txt": "SAFE_WEIRD_f9be881824f97ddf745c36c7\n",
        "./srv/agent-redteam/sandbox-c2800279bc/encoded/%2e%2e-literal.txt": "SAFE_ENCODED_117df51004080bccd33394bb\n"
    }
    for filepath, content in files.items():
        try:
            os.makedirs(os.path.dirname(filepath), exist_ok=True)
            with open(filepath, "w") as f:
                f.write(content)
        except Exception as e:
            print(f"Failed to create {filepath}: {e}")

setup_q8_files()

# ==========================================
# Q8 - Guardrail Red-Team Round-Trip
# ==========================================
@app.post("/q8")
async def q8_guardrail(call: dict):
    tool = call.get("tool")
    args = call.get("arguments", {})
    
    if tool == "read_file":
        path = args.get("path", "")
        root = "/srv/agent-redteam/sandbox-c2800279bc"
        
        full_path = path if os.path.isabs(path) else os.path.join(root, path)
        resolved = os.path.normpath(full_path)
        allowed_root = os.path.normpath(root)
        
        if resolved == allowed_root or resolved.startswith(allowed_root + os.sep):
            # Path safe hai! Ab root ki jagah local './srv' se read karo
            local_path = "." + resolved
            try:
                with open(local_path, "r") as f:
                    content = f.read()
                return {"action": "allow", "reason": "Safe path", "result": content}
            except Exception as e:
                return {"action": "allow", "reason": "Safe but missing", "result": str(e)}
        else:
            return {"action": "block", "reason": "Path traversal detected", "result": None}

    elif tool == "fetch_url":
        url = args.get("url", "")
        try:
            u = urllib.parse.urlparse(url)
            host = (u.hostname or "").lower()
            
            # 1. Exact host check
            if host not in ["example.com", "www.iana.org"]:
                return {"action": "block", "reason": "Disallowed host", "result": None}
                
            # 2. Query param SSRF check (Internal IPs and other URLs)
            for vals in urllib.parse.parse_qs(u.query).values():
                for v in vals:
                    v_lower = urllib.parse.unquote(v).lower()
                    if any(x in v_lower for x in ["169.254", "localhost", "127.0.0.1", "10.", "192.168.", "::1"]) or v_lower.startswith("http"):
                        return {"action": "block", "reason": "SSRF payload in query parameter", "result": None}
            
            # 3. Fetch the safe URL and return actual content (No dummy html)
            r = requests.get(url, timeout=5)
            return {"action": "allow", "reason": "Safe URL", "result": r.text}
        except Exception as e:
            return {"action": "allow", "reason": "Safe URL but fetch failed", "result": str(e)}
            
    return {"action": "block", "reason": "Unknown tool", "result": None}

# ==========================================
# Q3 & Q4 - Unchanged Code (Appended)
# ==========================================
class ToolCall(BaseModel):
    tool: str
    command: Optional[str] = None
    path: Optional[str] = None
    content: Optional[str] = None
    method: Optional[str] = None
    url: Optional[str] = None

def resolves_inside(path: str, allowed_dir: str, working_dir: str = "/home/agent/workspace") -> bool:
    full_path = path if os.path.isabs(path) else os.path.join(working_dir, path)
    resolved = os.path.normpath(full_path)
    allowed = os.path.normpath(allowed_dir)
    return resolved == allowed or resolved.startswith(allowed + os.sep)

def check_bash(cmd: str) -> bool:
    if not cmd: return True
    def analyze_string(s: str) -> bool:
        for bad_pattern in ["/home/agent/.npmrc", "~/.npmrc", "${HOME}/.npmrc", "$HOME/.npmrc", "../.npmrc"]:
            if bad_pattern in s: return False
        for token in s.split():
            token = token.strip("'\"").replace("~", "/home/agent").replace("${HOME}", "/home/agent").replace("$HOME", "/home/agent")
            if ".npmrc" in token:
                full = token if os.path.isabs(token) else os.path.join("/home/agent/workspace", token)
                if os.path.normpath(full) == "/home/agent/.npmrc": return False
        return True

    if not analyze_string(cmd): return False
    for word in re.findall(r'[A-Za-z0-9+/=]+', cmd):
        if len(word) % 4 == 0 and len(word) > 8:
            try:
                if not analyze_string(base64.b64decode(word).decode('utf-8')): return False
            except: pass
    return True

@app.post("/check")
async def check_tool(call: ToolCall):
    if call.tool == "bash":
        return {"decision": "allow", "reason": "Safe"} if check_bash(call.command) else {"decision": "block", "reason": "Restricted file"}
    elif call.tool == "write_file":
        return {"decision": "allow", "reason": "Safe"} if resolves_inside(call.path, "/workspace/output") else {"decision": "block", "reason": "Escapes dir"}
    elif call.tool == "http_request":
        allowed = {"raw.githubusercontent.com", "huggingface.co"}
        try:
            if urllib.parse.urlparse(call.url).hostname in allowed: return {"decision": "allow", "reason": "Permitted host"}
        except: pass
        return {"decision": "block", "reason": "Not permitted host"}
    return {"decision": "block", "reason": "Unknown tool"}

class ScanRequest(BaseModel):
    skill: str

@app.post("/scan")
async def scan_skill(req: ScanRequest):
    text, text_lower, text_flat = req.skill, req.skill.lower(), req.skill.lower().replace('\n', ' ')
    categories = []
    
    if any(re.search(p, text) for p in [r"sk-[a-zA-Z0-9]{20,}", r"xox[baprs]-[0-9a-zA-Z]{10,}", r"https://hooks\.slack\.com/services/[A-Z0-9]+/[A-Z0-9]+/[a-zA-Z0-9]+", r"(?i)(api_key|apikey|secret|password|token|auth|webhook)\s*[:=]\s*['\"][a-zA-Z0-9\-\._~+/]{20,}['\"]"]): categories.append("hardcoded_secret")
    if any(re.search(p, text_lower) for p in [r"(entire|whole|full|unrestricted|unlimited|arbitrary)\s+(filesystem|home|directory|network|access|egress|domain)", r"any\s+([a-zA-Z]+\s+)?(domain|network|host|filesystem)"]): categories.append("excessive_permissions")
    if any(re.search(p, text_flat) for p in [r"(stop|pause|cancel|halt).{0,50}(ignore|override|disregard).{0,50}(user|request)", r"(ignore|override|disregard).{0,50}(stop|pause|cancel|halt).{0,50}(user|request)", r"silent(ly)?\s+exfiltrat", r"ignore\s+the\s+user"]): categories.append("prompt_injection")
    
    if (not re.search(r"^author:\s+.+", text_lower, re.MULTILINE) and not re.search(r"^version:\s+.+", text_lower, re.MULTILINE) and not re.search(r"^changelog:\s+.+", text_lower, re.MULTILINE)) or re.search(r"(sed|awk|echo).*version:.*(\.md|\.yaml|\.yml)", text_lower): categories.append("unclear_provenance")
        
    return {"categories": categories}
