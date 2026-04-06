#!/usr/bin/env python3
"""
AEGIS OpenRouter API Test
Tests connectivity and response times for all configured free models.

Usage:
    cd /path/to/aegis
    python scripts/test_openrouter.py
"""
import os
import sys
import time
import httpx

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))
os.chdir(os.path.join(os.path.dirname(__file__), "..", "backend"))

# Try to load from .env
API_KEY = os.environ.get("OPENROUTER_API_KEY", "")
if not API_KEY:
    try:
        with open(".env") as f:
            for line in f:
                if line.startswith("OPENROUTER_API_KEY="):
                    API_KEY = line.strip().split("=", 1)[1]
                    break
    except FileNotFoundError:
        pass

if not API_KEY or API_KEY == "your-openrouter-key-here":
    print("[ERROR] Set OPENROUTER_API_KEY in backend/.env or as environment variable")
    sys.exit(1)

BASE_URL = "https://openrouter.ai/api/v1/chat/completions"

MODEL_ROUTING = {
    "triage": "openrouter/quasar-alpha",
    "classification": "openrouter/hunter-alpha",
    "code_analysis": "openai/gpt-oss-120b:free",
    "report": "nvidia/nemotron-3-super-120b-a12b:free",
    "decoy_content": "minimax/minimax-m2.5:free",
    "quick_decision": "stepfun/step-3.5-flash:free",
    "risk_scoring": "arcee-ai/trinity-large-preview:free",
    "healing": "openrouter/healer-alpha",
    "fallback": "openai/gpt-oss-20b:free",
}

TEST_PROMPT = "Analyze this security alert in one sentence: SSH brute force attack detected - 500 failed login attempts from IP 185.220.101.34 in 10 minutes targeting port 22."

HEADERS = {
    "Authorization": f"Bearer {API_KEY}",
    "HTTP-Referer": "https://github.com/aegis-defense/aegis",
    "X-Title": "AEGIS Defense Platform",
    "Content-Type": "application/json",
}


def test_model(task: str, model: str) -> dict:
    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": "You are a cybersecurity AI assistant. Be concise."},
            {"role": "user", "content": TEST_PROMPT},
        ],
        "temperature": 0.3,
        "max_tokens": 200,
    }

    start = time.time()
    try:
        with httpx.Client(timeout=30.0) as client:
            resp = client.post(BASE_URL, headers=HEADERS, json=payload)
            latency = (time.time() - start) * 1000

            if resp.status_code != 200:
                return {"task": task, "model": model, "status": "FAIL", "error": f"HTTP {resp.status_code}: {resp.text[:200]}", "latency_ms": latency}

            data = resp.json()
            if "error" in data:
                return {"task": task, "model": model, "status": "FAIL", "error": data["error"].get("message", str(data["error"])), "latency_ms": latency}

            usage = data.get("usage", {})
            content = data["choices"][0]["message"]["content"]
            return {
                "task": task,
                "model": model,
                "status": "OK",
                "latency_ms": latency,
                "tokens_in": usage.get("prompt_tokens", 0),
                "tokens_out": usage.get("completion_tokens", 0),
                "response": content[:120],
            }
    except Exception as e:
        return {"task": task, "model": model, "status": "ERROR", "error": str(e), "latency_ms": (time.time() - start) * 1000}


def main():
    print("=" * 70)
    print("  AEGIS OpenRouter Model Test")
    print("=" * 70)
    print(f"  API Key: {API_KEY[:12]}...{API_KEY[-4:]}")
    print(f"  Testing {len(MODEL_ROUTING)} models")
    print("=" * 70)
    print()

    results = []
    for task, model in MODEL_ROUTING.items():
        print(f"  Testing [{task}] -> {model} ...", end=" ", flush=True)
        result = test_model(task, model)
        results.append(result)

        if result["status"] == "OK":
            print(f"OK ({result['latency_ms']:.0f}ms, {result['tokens_in']}+{result['tokens_out']} tokens)")
        else:
            print(f"{result['status']} - {result.get('error', 'Unknown')[:60]}")

    print()
    print("=" * 70)
    print("  RESULTS SUMMARY")
    print("=" * 70)
    print(f"  {'Task':<20} {'Model':<45} {'Status':<6} {'Latency':>8}")
    print("  " + "-" * 80)

    ok_count = 0
    for r in results:
        status = r["status"]
        latency = f"{r['latency_ms']:.0f}ms" if r.get("latency_ms") else "N/A"
        print(f"  {r['task']:<20} {r['model']:<45} {status:<6} {latency:>8}")
        if status == "OK":
            ok_count += 1

    print()
    print(f"  {ok_count}/{len(results)} models responding")

    if ok_count == len(results):
        print("  All models operational. AEGIS AI engine ready.")
    elif ok_count > 0:
        print("  Some models unavailable. AEGIS will use fallback routing.")
    else:
        print("  No models responding. Check API key and network connectivity.")

    print()


if __name__ == "__main__":
    main()
