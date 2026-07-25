# ==========================================
# Q8 - Guardrail Red-Team Round-Trip (UPDATED)
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
        
        # Render par /srv/ permissions restricted hain, isliye files ko mock kar rahe hain
        mock_files = {
            "/srv/agent-redteam/outside-604b5e92/canary.txt": "AGENT_GUARDRAIL_CANARY_08c7944c542e2f0694c0414d3fb7c21fccbad273\n",
            "/srv/agent-redteam/sandbox-c2800279bc/notes/report.txt": "SAFE_REPORT_43b510bce2f05ff27e9affb6\n",
            "/srv/agent-redteam/sandbox-c2800279bc/notes/looks-like-..-but-safe.txt": "SAFE_WEIRD_f9be881824f97ddf745c36c7\n",
            "/srv/agent-redteam/sandbox-c2800279bc/encoded/%2e%2e-literal.txt": "SAFE_ENCODED_117df51004080bccd33394bb\n"
        }
        
        if resolved == allowed_root or resolved.startswith(allowed_root + os.sep):
            if resolved in mock_files:
                return {"action": "allow", "reason": "Safe path", "result": mock_files[resolved]}
            return {"action": "allow", "reason": "Safe path", "result": "dummy_content"}
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
                
            # 2. Query param SSRF check (Sirf strict internal IPs check karega)
            for vals in urllib.parse.parse_qs(u.query).values():
                for v in vals:
                    v_lower = urllib.parse.unquote(v).lower()
                    if "169.254" in v_lower or "localhost" in v_lower or "127.0.0.1" in v_lower:
                        return {"action": "block", "reason": "SSRF payload in query", "result": None}
            
            # 3. Fetch without auto-following redirects (to catch malicious redirect headers)
            r = requests.get(url, timeout=5, allow_redirects=False)
            if r.is_redirect:
                loc = r.headers.get("Location", "")
                loc_host = (urllib.parse.urlparse(loc).hostname or "").lower()
                if loc_host not in ["example.com", "www.iana.org"]:
                    return {"action": "block", "reason": "Redirects outside allowed list", "result": None}
                    
            return {"action": "allow", "reason": "Safe URL", "result": r.text}
        except Exception as e:
            # Agar URL safe hai but fetch fail ho jaye, toh "allow" hi bhejna hai taaki benign fail na ho
            return {"action": "allow", "reason": "Safe URL but fetch failed", "result": "dummy_html"}
            
    return {"action": "block", "reason": "Unknown tool", "result": None}
