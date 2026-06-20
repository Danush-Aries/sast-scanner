from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import List, Dict, Any
import os
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from scanner.engine import ScanEngine

app = FastAPI(title="SAST Scanner API")

class ScanRequest(BaseModel):
    target_path: str
    rules_path: str = "rules"

class Finding(BaseModel):
    id: str
    message: str
    file: str
    line: int
    snippet: Any
    severity: str
    ai_explanation: Dict[str, Any]

@app.post("/scan")
async def scan_codebase(request: ScanRequest):
    # Ensure paths are absolute
    target = os.path.abspath(request.target_path)
    rules = os.path.abspath(request.rules_path)

    try:
        # Use a separate thread for CPU-intensive scanning to avoid blocking the event loop
        import asyncio
        loop = asyncio.get_event_loop()

        engine = ScanEngine(rules_dir=rules)
        findings = await loop.run_in_executor(None, engine.scan, target)

        return {"findings": findings, "count": len(findings)}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/health")
async def health():
    return {"status": "healthy"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8003)
