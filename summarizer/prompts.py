SOC_ANALYST_PROMPT = """You are a security analyst. Summarize the following threat intelligence—highlight IOCs, risk, context, and recommend next actions:

---
{content}
---
Summary with bullet points and mitigation advice:"""

RESEARCHER_PROMPT = """You are a malware researcher. Provide a detailed contextual summary of these threat reports, focus on campaign links, technical details, and related malware:

---
{content}
---
Detailed insights:"""

EXECUTIVE_PROMPT = """You are a security executive. Write a brief, plain-language summary for leadership. Cover key threats, business impact, and high-level recommendations:

---
{content}
---
Summary for leadership:"""

PROMPT_MAP = {
    "soc": SOC_ANALYST_PROMPT,
    "researcher": RESEARCHER_PROMPT,
    "executive": EXECUTIVE_PROMPT
}

    