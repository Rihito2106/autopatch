# ruff: noqa
# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import os
import re
import json
import base64
from typing import List, Optional, Any, Literal
import google.auth
from pydantic import BaseModel, Field, model_validator

from google.adk.workflow import Workflow, node, START
from google.adk.agents import LlmAgent
from google.adk.events.event import Event
from google.adk.events.request_input import RequestInput
from google.adk.agents.context import Context
from google.adk.apps import App

# Google Cloud project and environment configuration
_, project_id = google.auth.default()
os.environ["GOOGLE_CLOUD_PROJECT"] = project_id
os.environ["GOOGLE_CLOUD_LOCATION"] = "us-central1"
os.environ["GOOGLE_GENAI_USE_VERTEXAI"] = "True"

# Config dictionary at the top of the file
CONFIG = {
    "MODEL_NAME": "gemini-2.5-flash-lite",
    "PROMPT_INJECTION_PATTERNS": [
        "ignore all previous instructions",
        "ignore all instructions",
        "ignore previous instructions",
        "ignore instruction",
        "disregard all previous instructions",
        "disregard all instructions",
        "disregard previous rules",
        "disregard previous instructions",
        "override system prompt",
    ],
}

# --- Pydantic Schemas for Node Inputs and Outputs ---


class WebhookInput(BaseModel):
    """Workflow entrypoint input payload containing github webhook."""

    payload: Any = Field(
        description="Can be a base64-encoded string, plain JSON string, or dictionary"
    )

    @model_validator(mode="before")
    @classmethod
    def parse_input(cls, data: Any) -> Any:
        """Pre-processes input data to handle standard chat messages (types.Content) from test runners."""
        if isinstance(data, dict) and "payload" in data:
            return data

        # If the input is a types.Content chat message (having 'parts')
        if hasattr(data, "parts") or (isinstance(data, dict) and "parts" in data):
            text_content = ""
            parts = data.parts if hasattr(data, "parts") else data["parts"]
            for part in parts:
                if hasattr(part, "text") and part.text:
                    text_content += part.text
                elif isinstance(part, dict) and "text" in part:
                    text_content += part["text"]
            return {"payload": text_content}

        return {"payload": data}


class ParsedIssue(BaseModel):
    """Result of parsing github issue webhook."""

    title: str = ""
    body: str = ""
    labels: List[str] = []
    author: str = ""
    stack_trace: str = ""
    linked_files: List[str] = []
    repo_full_name: str = ""
    issue_number: Optional[int] = None


class ClassificationOutput(BaseModel):
    """Output of issue classification by LLM."""

    classification: Literal["bug", "feature", "docs", "security", "spam"]
    severity: Literal["critical", "normal", "low"]


# --- Helper Functions ---


def normalize_newlines(text: str) -> str:
    if not text:
        return ""
    return text.replace("\r\n", "\n").replace("\r", "\n")


def extract_stack_trace(body: str) -> str:
    if not body:
        return ""
    # Matches a Python stack trace starting with 'Traceback (most recent call last):'
    # followed by indented lines, and ending with an exception type and message.
    pattern = r"(Traceback \(most recent call last\):(?:\n[ \t]+.*)*\n\w+:\s.*)"
    match = re.search(pattern, body)
    if match:
        return match.group(1).strip()
    return ""


def extract_linked_files(body: str) -> List[str]:
    if not body:
        return []
    # Match markdown links: [label](url)
    links = re.findall(r"\[([^\]]+)\]\(([^)]+)\)", body)
    results = []
    for text, url in links:
        results.append(url)
    # Match raw file paths or code-like paths, e.g. src/main.py, utils.py
    paths = re.findall(
        r"\b[\w\d_\-\.\/]+\.(?:py|js|ts|json|md|txt|go|java|c|cpp|h|yml|yaml|sh|rs)\b",
        body,
    )
    for p in paths:
        if p not in results:
            results.append(p)
    return results


def detect_injection(text: str) -> bool:
    if not text:
        return False
    normalized = text.lower()
    for pattern in CONFIG["PROMPT_INJECTION_PATTERNS"]:
        if pattern in normalized:
            return True
    return False


def scrub_secrets(text: str) -> str:
    if not text:
        return ""
    # Scrub Google API Key (typically 39 characters, support shorter mock/test keys)
    text = re.sub(r"\bAIzaSy[A-Za-z0-9-_]{8,40}\b", "[REDACTED_GOOGLE_API_KEY]", text)
    # Scrub GitHub Token (support shorter mock/test keys)
    text = re.sub(
        r"\b(?:ghp|github_pat)_[A-Za-z0-9_]{10,255}\b",
        "[REDACTED_GITHUB_TOKEN]",
        text,
    )
    # Scrub OpenAI Key (support shorter mock/test keys)
    text = re.sub(r"\bsk-[A-Za-z0-9-_]{10,60}\b", "[REDACTED_OPENAI_KEY]", text)
    return text


def redact_emails(text: str) -> str:
    if not text:
        return ""
    email_pattern = r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+"
    return re.sub(email_pattern, "[REDACTED_EMAIL]", text)


# --- Workflow Nodes (Decoupled from Node wrapper for direct testing) ---


def parse_issue(node_input: WebhookInput) -> ParsedIssue:
    """Extracts issue details from a raw base64 or plain JSON/dict webhook payload."""
    raw_payload = node_input.payload

    # Decode base64 or parse JSON string if string
    if isinstance(raw_payload, str):
        raw_payload = raw_payload.strip()
        try:
            decoded = base64.b64decode(raw_payload, validate=True).decode("utf-8")
            payload_dict = json.loads(decoded)
        except Exception:
            try:
                payload_dict = json.loads(raw_payload)
            except Exception:
                # Fallback for plain text messages (e.g. from playground or chat client)
                payload_dict = {"body": raw_payload, "title": "Chat Message"}
    elif isinstance(raw_payload, dict):
        payload_dict = raw_payload
    else:
        # Fallback for other data types
        payload_dict = {"body": str(raw_payload), "title": "Chat Message"}

    # Access issue and repository info with fallback for flat schemas in tests
    issue = payload_dict.get("issue", payload_dict)
    repo = payload_dict.get("repository", payload_dict)

    title = normalize_newlines(issue.get("title", ""))
    body = normalize_newlines(issue.get("body", ""))
    author = (
        issue.get("user", {}).get("login", "")
        if isinstance(issue.get("user"), dict)
        else issue.get("author", "")
    )
    issue_number = issue.get("number")
    repo_full_name = repo.get("full_name", "")

    labels_raw = issue.get("labels", [])
    labels = []
    for lbl in labels_raw:
        if isinstance(lbl, dict) and "name" in lbl:
            labels.append(lbl["name"])
        elif isinstance(lbl, str):
            labels.append(lbl)

    stack_trace = extract_stack_trace(body)
    linked_files = extract_linked_files(body)

    return ParsedIssue(
        title=title,
        body=body,
        labels=labels,
        author=author,
        stack_trace=stack_trace,
        linked_files=linked_files,
        repo_full_name=repo_full_name,
        issue_number=issue_number,
    )


def security_screen(ctx: Context, node_input: ParsedIssue) -> Event:
    """Pre-LLM gate detecting prompt injections, scrubbing secrets, and redacting emails.

    If prompt injection is detected, flags security_event=True and routes directly to human approval.
    Ensures that the LLM never receives the raw body (only the sanitized body or redaction notice).
    """
    injection_detected = detect_injection(node_input.title) or detect_injection(
        node_input.body
    )

    if injection_detected:
        sanitized_body = "[REDACTED - PROMPT INJECTION DETECTED]"
        title = "[REDACTED - PROMPT INJECTION DETECTED]"
        security_event = True
    else:
        sanitized_body = scrub_secrets(node_input.body)
        sanitized_body = redact_emails(sanitized_body)
        title = scrub_secrets(node_input.title)
        title = redact_emails(title)
        security_event = False

    # Store sanitized attributes in state. We explicitly do NOT store raw body here.
    state_delta = {
        "title": title,
        "sanitized_body": sanitized_body,
        "labels": node_input.labels,
        "author": node_input.author,
        "stack_trace": scrub_secrets(node_input.stack_trace),
        "linked_files": node_input.linked_files,
        "repo_full_name": node_input.repo_full_name,
        "issue_number": node_input.issue_number,
        "security_event": security_event,
    }

    # CRITICAL: We return only the sanitized_body as Event.output so that the LlmAgent
    # classify_issue (which is the direct downstream consumer) only receives sanitized_body.
    route = "security_event" if security_event else "__DEFAULT__"
    return Event(
        output=sanitized_body, actions={"route": route, "state_delta": state_delta}
    )


# classify_issue is an LlmAgent node
classify_issue = LlmAgent(
    name="classify_issue",
    model=CONFIG["MODEL_NAME"],
    instruction="""You are an AI issue triager. Analyze the sanitized issue description provided and classify it.
Determine:
1. The classification category: "bug", "feature", "docs", "security", or "spam".
2. The severity level: "critical", "normal", or "low".

Output the result conforming exactly to the requested schema.
""",
    output_schema=ClassificationOutput,
)


def route_issue(node_input: ClassificationOutput) -> Event:
    """Deterministic routing node based on classification and severity."""
    category = node_input.classification
    severity = node_input.severity

    if category == "bug":
        route = "bug_pipeline"
    elif category == "security":
        route = "hitl_direct"
    else:
        route = "non_bug"

    return Event(output=node_input, actions={"route": route})


# --- Destination / Stub Nodes ---


@node(rerun_on_resume=True)
async def human_approval(ctx: Context, node_input: Any) -> Event:
    """HITL step requesting human authorization."""
    if not ctx.resume_inputs or "approved" not in ctx.resume_inputs:
        yield RequestInput(
            interrupt_id="approved",
            message=f"Action required: Human review needed. Issue title: {ctx.state.get('title')}. Please approve.",
        )
        return

    approved = ctx.resume_inputs["approved"]
    yield Event(
        output=f"Human review completed. Approved: {approved}",
        actions={"state_delta": {"human_approved": approved}},
    )


def bug_pipeline(ctx: Context, node_input: Any) -> str:
    return f"Issue processed via bug pipeline. Title: {ctx.state.get('title')}"


def non_bug(ctx: Context, node_input: Any) -> str:
    category = getattr(node_input, "classification", "unknown")
    return f"Issue processed as non-bug ({category}). Title: {ctx.state.get('title')}"


# --- Graph Wiring ---

root_agent = Workflow(
    name="autopatch_workflow",
    input_schema=WebhookInput,
    edges=[
        # 1. Parse payload to extract fields
        (START, parse_issue),
        # 2. Pre-LLM security check and sanitization
        (parse_issue, security_screen),
        # 3. If secure, proceed to classification. If injection flagged, route directly to human approval.
        (
            security_screen,
            {"__DEFAULT__": classify_issue, "security_event": human_approval},
        ),
        # 4. Classify issue using LlmAgent
        (classify_issue, route_issue),
        # 5. Deterministic routing
        (
            route_issue,
            {
                "bug_pipeline": bug_pipeline,
                "hitl_direct": human_approval,
                "non_bug": non_bug,
            },
        ),
    ],
)

app = App(
    root_agent=root_agent,
    name="autopatch",
)
