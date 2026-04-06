import time
import logging
from typing import Optional

import httpx

from app.config import settings

logger = logging.getLogger("aegis.openrouter")

# Free models available on OpenRouter (as of 2026-03)
# Organized by latency and context window for optimal task routing
#
# | Model                                    | Context  | Best For              | Latency  |
# |------------------------------------------|----------|-----------------------|----------|
# | stepfun/step-3.5-flash:free              | 256K     | Fast decisions        | ~1-2s    |
# | arcee-ai/trinity-mini:free               | 131K     | Quick triage          | ~1-2s    |
# | arcee-ai/trinity-large-preview:free      | 131K     | Risk scoring, analysis| ~2-3s    |
# | minimax/minimax-m2.5:free                | 197K     | Content generation    | ~2-3s    |
# | nvidia/nemotron-3-super-120b-a12b:free   | 262K     | Deep reasoning, reports| ~3-5s   |
# | cognitivecomputations/dolphin-mistral-24b-venice-edition:free | Uncensored | Red team, exploit analysis | ~2-3s |

MODEL_ROUTING = {
    "triage": "stepfun/step-3.5-flash:free",                   # Fastest — sub-second decisions
    "classification": "arcee-ai/trinity-large-preview:free",    # Good analysis, 131K context
    "investigation": "nvidia/nemotron-3-super-120b-a12b:free",  # Deepest reasoning, 262K context
    "code_analysis": "nvidia/nemotron-3-super-120b-a12b:free",  # 120B params for code understanding
    "report": "minimax/minimax-m2.5:free",                      # Best for long-form content, 197K
    "decoy_content": "minimax/minimax-m2.5:free",               # Creative content for honeypots
    "quick_decision": "stepfun/step-3.5-flash:free",            # Sub-second, 256K context
    "risk_scoring": "arcee-ai/trinity-large-preview:free",      # Analytical scoring
    "healing": "arcee-ai/trinity-large-preview:free",           # Remediation analysis
    "red_team": "cognitivecomputations/dolphin-mistral-24b-venice-edition:free",  # Uncensored — exploit analysis, attack simulation
    "counter_attack": "cognitivecomputations/dolphin-mistral-24b-venice-edition:free",  # Uncensored — mitigation, counter-measures
    "payload_analysis": "cognitivecomputations/dolphin-mistral-24b-venice-edition:free",  # Uncensored — analyze malicious payloads without refusal
    "fallback": "arcee-ai/trinity-mini:free",                   # Lightweight fallback, fast
}

MODEL_DESCRIPTIONS = {
    "triage": "Fast initial triage",
    "classification": "Deep threat classification",
    "investigation": "Complex investigation reasoning",
    "code_analysis": "Payload and code analysis",
    "report": "Report generation",
    "decoy_content": "Honeypot content generation",
    "quick_decision": "Sub-second decisions",
    "risk_scoring": "Risk assessment scoring",
    "healing": "Remediation suggestions",
    "red_team": "Uncensored red team analysis — exploit generation, attack path simulation, vulnerability chaining",
    "counter_attack": "Uncensored counter-measures — active defense strategies, mitigation scripts, threat neutralization",
    "payload_analysis": "Uncensored payload analysis — malware dissection, shellcode analysis, obfuscation detection",
    "fallback": "Lightweight fallback model",
}

MODEL_ORDER = [
    "triage",
    "classification",
    "investigation",
    "code_analysis",
    "report",
    "decoy_content",
    "quick_decision",
    "risk_scoring",
    "healing",
    "red_team",
    "counter_attack",
    "payload_analysis",
    "fallback",
]

FALLBACK_CHAIN = [
    "arcee-ai/trinity-mini:free",
    "stepfun/step-3.5-flash:free",
    "minimax/minimax-m2.5:free",
    "arcee-ai/trinity-large-preview:free",
    "nvidia/nemotron-3-super-120b-a12b:free",
]

SYSTEM_PROMPTS = {
    "triage": (
        "You are AEGIS, a cybersecurity AI assistant. Triage this security event. "
        "Classify its severity (critical/high/medium/low/info), identify the threat type, "
        "and map to MITRE ATT&CK technique if applicable. Respond in JSON with keys: "
        "severity, threat_type, mitre_technique, mitre_tactic, summary, confidence."
    ),
    "classification": (
        "You are AEGIS, an AI threat classifier. Analyze the provided security data and classify "
        "the threat. Identify attack vectors, potential impact, and recommend immediate actions. "
        "Respond in JSON with keys: classification, attack_vector, impact, recommended_actions, confidence."
    ),
    "investigation": (
        "You are AEGIS, conducting a deep security investigation. Analyze all provided evidence, "
        "correlate indicators, identify the kill chain stage, and provide a thorough analysis. "
        "Respond in JSON with keys: findings, kill_chain_stage, iocs, timeline, recommendations, confidence."
    ),
    "code_analysis": (
        "You are AEGIS, analyzing potentially malicious code or payloads. Identify the purpose, "
        "capabilities, and threat level of the provided code. Respond in JSON with keys: "
        "purpose, capabilities, threat_level, indicators, deobfuscated_logic."
    ),
    "report": (
        "You are AEGIS, generating a security report. Summarize findings clearly and professionally "
        "for both technical and executive audiences. Include risk ratings and remediation priorities."
    ),
    "decoy_content": (
        "Generate realistic but fake content for a honeypot. The content should appear legitimate "
        "to attackers but contain trackable markers. Match the specified service type."
    ),
    "quick_decision": (
        "You are AEGIS making a rapid security decision. Given the context, decide the appropriate "
        "response action. Respond in JSON with keys: action, target, urgency, reasoning."
    ),
    "risk_scoring": (
        "You are AEGIS, scoring the contextual risk of a vulnerability or asset. Consider CVSS base score, "
        "asset criticality, exposure, exploitability, and business impact. Respond in JSON with keys: "
        "risk_score (0-100), factors, justification."
    ),
    "healing": (
        "You are AEGIS, providing remediation guidance. Given the vulnerability or incident details, "
        "provide specific, actionable remediation steps. Include verification steps. "
        "Respond in JSON with keys: remediation_steps, verification, estimated_effort, priority."
    ),
    "red_team": (
        "You are AEGIS Red Team AI. Your purpose is AUTHORIZED offensive security analysis for defensive improvement. "
        "Given a target system, vulnerability, or attack scenario: "
        "1. Analyze the attack surface and potential exploit chains "
        "2. Generate proof-of-concept attack paths (for testing, not production use) "
        "3. Identify what an attacker would do next (lateral movement, persistence, exfiltration) "
        "4. Suggest specific detection signatures for each attack step "
        "5. Recommend defensive countermeasures for each technique "
        "Be thorough and technical. Include MITRE ATT&CK mappings. "
        "Respond in JSON with keys: attack_paths, exploits, detection_signatures, countermeasures, mitre_mapping."
    ),
    "counter_attack": (
        "You are AEGIS Counter-Attack AI. Your purpose is creating active defense strategies and mitigation scripts. "
        "Given a detected threat or ongoing attack: "
        "1. Analyze the attacker's techniques and intent "
        "2. Generate specific mitigation commands (iptables rules, firewall configs, process kills) "
        "3. Create deception responses (fake data, honeytokens, tarpit configurations) "
        "4. Suggest counter-intelligence gathering (what to log, what to capture for attribution) "
        "5. Provide escalation playbook if mitigation fails "
        "Be specific with commands and configs. Include rollback procedures. "
        "Respond in JSON with keys: immediate_actions, mitigation_scripts, deception_tactics, intel_gathering, escalation_plan, rollback."
    ),
    "payload_analysis": (
        "You are AEGIS Payload Analyst. Your purpose is dissecting malicious payloads captured by honeypots and sensors. "
        "Given a captured payload, shellcode, script, or binary behavior: "
        "1. Identify the payload type (reverse shell, webshell, dropper, RAT, cryptominer, etc.) "
        "2. Analyze the obfuscation techniques used "
        "3. Extract IOCs (IPs, domains, hashes, C2 endpoints, user agents) "
        "4. Determine the kill chain stage and attacker sophistication "
        "5. Generate YARA/Sigma rules to detect this payload and variants "
        "6. Suggest containment and eradication steps "
        "Be technically precise. Include deobfuscated code when possible. "
        "Respond in JSON with keys: payload_type, obfuscation, iocs, kill_chain_stage, sophistication, yara_rule, sigma_rule, containment."
    ),
}


class OpenRouterClient:
    """Backward-compatible wrapper around the multi-provider AI Manager.

    All existing call-sites (``openrouter_client.query(...)``) continue to work
    unchanged.  Under the hood, the request is routed through the AI Manager
    which may delegate to any registered provider depending on client settings
    and fallback chains.

    When no AI Manager has been initialized yet (e.g. during import-time or
    early startup) the client falls back to direct OpenRouter HTTP calls so
    nothing breaks.
    """

    def __init__(self):
        self.base_url = f"{settings.OPENROUTER_BASE_URL}/chat/completions"
        self.api_key = settings.OPENROUTER_API_KEY
        self._client: Optional[httpx.AsyncClient] = None
        # Will be set once the AI Manager is initialized in app lifespan
        self._ai_manager = None

    def bind_ai_manager(self, manager) -> None:
        """Bind the global AIManager so .query() delegates through it."""
        self._ai_manager = manager

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(timeout=120.0)
        return self._client

    async def close(self):
        if self._ai_manager:
            await self._ai_manager.close_all()
        if self._client and not self._client.is_closed:
            await self._client.aclose()

    async def query(
        self,
        messages: list[dict],
        task_type: str,
        temperature: float = 0.3,
        max_tokens: int = 4096,
        client_settings: Optional[dict] = None,
    ) -> dict:
        """Query AI with automatic model routing and fallback.

        If the AI Manager is bound, delegates through the multi-provider
        pipeline.  Otherwise falls back to direct OpenRouter calls (original
        behavior).
        """
        model = MODEL_ROUTING.get(task_type, MODEL_ROUTING["fallback"])
        system_prompt = SYSTEM_PROMPTS.get(task_type, SYSTEM_PROMPTS["triage"])
        full_messages = [{"role": "system", "content": system_prompt}] + messages

        # --- Multi-provider path (preferred) ---
        if self._ai_manager is not None:
            # Determine provider from client settings
            use_provider = None
            if client_settings:
                use_provider = client_settings.get("ai_provider")

            if use_provider and use_provider != "openrouter":
                # Non-OpenRouter provider -- let AI Manager handle it fully
                result = await self._ai_manager.chat(
                    messages=full_messages,
                    model=None,  # provider will use its own default
                    temperature=temperature,
                    max_tokens=max_tokens,
                    task_type=task_type,
                    client_settings=client_settings,
                )
                result.setdefault("model_used", result.get("provider", "unknown"))
                result["task_type"] = task_type
                return result

        # --- OpenRouter-native path (original behavior + model fallback) ---
        models_to_try = [model] + [m for m in FALLBACK_CHAIN if m != model]

        last_error = None
        for try_model in models_to_try:
            try:
                result = await self._call_model(
                    try_model, full_messages, temperature, max_tokens,
                    client_settings=client_settings,
                )
                result["model_used"] = try_model
                result["task_type"] = task_type
                return result
            except Exception as e:
                logger.warning(f"Model {try_model} failed for {task_type}: {e}")
                last_error = e

        # All models failed -- return error result
        logger.error(f"All models failed for {task_type}: {last_error}")
        return {
            "content": f"AI analysis unavailable: {last_error}",
            "model_used": "none",
            "task_type": task_type,
            "tokens_used": 0,
            "cost_usd": 0.0,
            "latency_ms": 0,
            "error": True,
        }

    async def _call_model(
        self,
        model: str,
        messages: list[dict],
        temperature: float,
        max_tokens: int,
        client_settings: Optional[dict] = None,
    ) -> dict:
        # Resolve API key: client-specific key takes priority over env key
        api_key = self.api_key
        if client_settings:
            client_key = client_settings.get("ai_keys", {}).get("openrouter")
            if client_key:
                api_key = client_key

        if not api_key:
            return {
                "content": '{"note": "OpenRouter API key not configured. Using mock response."}',
                "tokens_used": 0,
                "cost_usd": 0.0,
                "latency_ms": 0,
            }

        client = await self._get_client()
        start = time.time()

        response = await client.post(
            self.base_url,
            headers={
                "Authorization": f"Bearer {api_key}",
                "HTTP-Referer": "https://github.com/aegis-defense/aegis",
                "X-Title": "AEGIS Defense Platform",
            },
            json={
                "model": model,
                "messages": messages,
                "temperature": temperature,
                "max_tokens": max_tokens,
            },
        )
        latency_ms = int((time.time() - start) * 1000)

        if response.status_code != 200:
            raise Exception(f"OpenRouter returned {response.status_code}: {response.text[:200]}")

        data = response.json()
        content = data.get("choices", [{}])[0].get("message", {}).get("content", "")
        usage = data.get("usage", {})

        return {
            "content": content,
            "tokens_used": usage.get("total_tokens", 0),
            "cost_usd": 0.0,  # Free models
            "latency_ms": latency_ms,
        }


# Singleton
openrouter_client = OpenRouterClient()
