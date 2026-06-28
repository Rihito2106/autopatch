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
from dotenv import load_dotenv

load_dotenv()

import re
import json
import base64
from typing import List, Optional, Any, Literal
import google.auth
from pydantic import BaseModel, Field, model_validator

import docker
import requests
from google.adk.tools.mcp_tool import McpToolset
from google.adk.tools.mcp_tool.mcp_session_manager import SseConnectionParams, StdioConnectionParams
from mcp import StdioServerParameters

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


class ReproductionResult(BaseModel):
    """Output of reproduction run in Docker container."""

    reproduced: bool = Field(description="Whether the bug was successfully reproduced")
    failing_tests: List[str] = Field(
        default_factory=list, description="List of failing test names/IDs"
    )
    traceback: str = Field(description="The traceback or test execution output")
    reproduction_command: str = Field(
        description="The command used to reproduce the bug"
    )


class RootCauseOutput(BaseModel):
    """Output of root cause analysis LlmAgent."""

    explanation: str = Field(description="Explanation of the root cause of the bug")
    files_to_modify: List[str] = Field(
        description="List of files that need to be modified relative to the repo root"
    )


class FixProposal(BaseModel):
    """Output of propose fix LlmAgent."""

    explanation: str = Field(description="Explanation of the proposed fix")
    diff: str = Field(description="Unified diff containing the proposed changes")


class NonBugOutput(BaseModel):
    """Output of handle non bug LlmAgent."""

    explanation: str = Field(
        description="Explanation of how the non-bug issue was handled"
    )
    label_added: str = Field(description="The label that was added to the issue")
    comment_body: str = Field(description="The body of the comment added to the issue")


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


def get_modified_files(diff_str: str) -> List[str]:
    modified_files = []
    if not diff_str:
        return modified_files
    for line in diff_str.splitlines():
        if line.startswith("+++ "):
            filename = line[4:].strip()
            if filename.startswith("b/"):
                filename = filename[2:]
            filename = filename.split("\t")[0].strip()
            modified_files.append(filename)
    return modified_files


def fetch_github_file(owner: str, repo: str, path: str, token: str) -> str:
    url = f"https://api.github.com/repos/{owner}/{repo}/contents/{path}"
    headers = {}
    if token:
        if token.startswith("github_pat") or token.startswith("ghp_"):
            headers["Authorization"] = f"token {token}"
        else:
            headers["Authorization"] = f"Bearer {token}"
    headers["Accept"] = "application/vnd.github.v3.raw"
    resp = requests.get(url, headers=headers)
    if resp.status_code == 200:
        return resp.text
    else:
        raise RuntimeError(
            f"Failed to fetch {path} from GitHub: {resp.status_code} {resp.text}"
        )


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

    # Access issue info with fallback for flat schemas in tests
    issue = payload_dict.get("issue", payload_dict)

    title = normalize_newlines(issue.get("title", ""))
    body = normalize_newlines(issue.get("body", ""))
    author = (
        issue.get("user", {}).get("login", "")
        if isinstance(issue.get("user"), dict)
        else issue.get("author", "")
    )

    # repo_full_name: try flat key first, fall back to nested
    repo_full_name = payload_dict.get("repo_full_name")
    if not repo_full_name:
        repo = payload_dict.get("repository")
        if isinstance(repo, dict):
            repo_full_name = repo.get("full_name", "")
        else:
            repo_full_name = ""

    # issue_number: try flat key first, fall back to nested
    issue_number = payload_dict.get("issue_number")
    if issue_number is None:
        issue_nested = payload_dict.get("issue")
        if isinstance(issue_nested, dict):
            issue_number = issue_nested.get("number")

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
    """HITL step requesting human authorization with full reviewer package."""
    if not ctx.resume_inputs or "approved" not in ctx.resume_inputs:
        title = ctx.state.get("title", "")
        body = ctx.state.get("sanitized_body", "")
        explanation = ctx.state.get("explanation", "")
        diff = ctx.state.get("proposed_diff", "")
        security_findings = ctx.state.get("security_findings", "")
        security_status = ctx.state.get("security_status", "")
        repro_cmd = ctx.state.get("reproduction_command", "")

        msg = f"=== ACTION REQUIRED: Human Review ===\n"
        msg += f"Issue Title: {title}\n"
        msg += f"Issue Body:\n{body}\n\n"

        if explanation:
            msg += f"## Root Cause Summary\n{explanation}\n\n"

        if diff:
            msg += f"## Proposed Changes\n```diff\n{diff}\n```\n\n"

        if security_findings:
            flag = "🚨 CRITICAL FINDINGS DETECTED 🚨" if security_status == "critical" else "⚠️ WARNING FINDINGS"
            msg += f"## Security Audit ({flag})\n{security_findings}\n\n"

        if repro_cmd:
            msg += f"## Reproduction Command\n`{repro_cmd}`\n\n"

        msg += "Please review the proposed patch and select response options:\n"
        msg += "- 'approve' to open a Pull Request\n"
        msg += "- 'reject' to close the issue with a rejection comment."

        yield RequestInput(
            interrupt_id="approved",
            message=msg,
        )
        return

    approved = ctx.resume_inputs["approved"]
    approved_str = str(approved).strip().lower()

    # Route: approve -> open_pr; reject -> close_with_comment
    route = "approve" if approved_str == "approve" else "reject"

    yield Event(
        output=f"Human review completed. Chosen action: {route}",
        actions={
            "route": route,
            "state_delta": {"human_approved": approved_str}
        },
    )


# --- GitHub MCP Toolset Configuration ---


github_mcp = McpToolset(
    connection_params=SseConnectionParams(
        url="https://api.githubcopilot.com/mcp/",
    ),
    header_provider=lambda ctx=None: {
        "Authorization": f"Bearer {os.environ.get('GITHUB_TOKEN', '')}"
    },
)


semgrep_mcp = McpToolset(
    connection_params=StdioConnectionParams(
        server_params=StdioServerParameters(
            command="uvx",
            args=["semgrep-mcp"],
        )
    )
)


# --- Bug Pipeline Nodes ---


def reproduce_bug(ctx: Context, node_input: Any) -> Event:
    """Clones the repository at HEAD, builds it, isolates network, and runs pytest inside Docker."""
    import logging
    import traceback

    logger = logging.getLogger("autopatch.reproduce_bug")

    try:
        repo_full_name = ctx.state.get("repo_full_name", "")
        github_token = os.environ.get("GITHUB_TOKEN", "")

        if not repo_full_name:
            logger.error("No repository specified in the context.")
            return Event(
                output=ReproductionResult(
                    reproduced=False,
                    failing_tests=[],
                    traceback="No repository specified in the context.",
                    reproduction_command="pytest --tb=short",
                ),
                actions={
                    "state_delta": {
                        "reproduced": False,
                        "failing_tests": [],
                        "reproducer_traceback": "No repository specified in the context.",
                        "reproduction_command": "pytest --tb=short",
                    }
                },
            )

        logger.info("Initializing Docker client...")
        try:
            client = docker.from_env()
        except Exception as e:
            err_msg = f"Docker client initialization failed: {e}"
            logger.error(err_msg)
            return Event(
                output=ReproductionResult(
                    reproduced=False,
                    failing_tests=[],
                    traceback=err_msg,
                    reproduction_command="pytest --tb=short",
                ),
                actions={
                    "state_delta": {
                        "reproduced": False,
                        "failing_tests": [],
                        "reproducer_traceback": err_msg,
                        "reproduction_command": "pytest --tb=short",
                    }
                },
            )

        image_name = "python:3.11"
        logger.info("Pulling python:3.11 image...")
        try:
            client.images.pull(image_name)
        except Exception as e:
            err_msg = f"Failed to pull image {image_name}: {e}"
            logger.error(err_msg)
            return Event(
                output=ReproductionResult(
                    reproduced=False,
                    failing_tests=[],
                    traceback=err_msg,
                    reproduction_command="pytest --tb=short",
                ),
                actions={
                    "state_delta": {
                        "reproduced": False,
                        "failing_tests": [],
                        "reproducer_traceback": err_msg,
                        "reproduction_command": "pytest --tb=short",
                    }
                },
            )

        logger.info("Image pulled. Creating container...")
        container = None
        try:
            container = client.containers.run(
                image_name, "tail -f /dev/null", detach=True
            )
            logger.info(f"Container created: {container.id}")
        except Exception as e:
            err_msg = f"Failed to run container: {e}"
            logger.error(err_msg)
            return Event(
                output=ReproductionResult(
                    reproduced=False,
                    failing_tests=[],
                    traceback=err_msg,
                    reproduction_command="pytest --tb=short",
                ),
                actions={
                    "state_delta": {
                        "reproduced": False,
                        "failing_tests": [],
                        "reproducer_traceback": err_msg,
                        "reproduction_command": "pytest --tb=short",
                    }
                },
            )

        reproduced = False
        failing_tests = []
        traceback_str = ""
        reproduction_command = "pytest --tb=short"

        try:
            logger.info(f"Cloning repo: {repo_full_name}...")
            if github_token:
                clone_url = f"https://x-access-token:{github_token}@github.com/{repo_full_name}.git"
            else:
                clone_url = f"https://github.com/{repo_full_name}.git"

            clone_cmd = f"git clone {clone_url} repo"
            exec_res = container.exec_run(f"bash -c '{clone_cmd}'")
            if exec_res.exit_code != 0:
                raise RuntimeError(
                    f"Git clone failed with code {exec_res.exit_code}: {exec_res.output.decode('utf-8', errors='replace')}"
                )

            logger.info("Installing dependencies...")
            install_cmd = (
                "cd repo && "
                "( [ ! -f requirements.txt ] || pip install -r requirements.txt ) && "
                "( [ -f requirements.txt ] || [ ! -f pyproject.toml ] || pip install -e \".[test]\" --no-deps ) && "
                "pip install pytest"
            )
            install_res = container.exec_run(f"bash -c '{install_cmd}'")
            install_output = install_res.output.decode('utf-8', errors='replace')
            if install_res.exit_code != 0:
                logger.error(f"Dependency installation failed with code {install_res.exit_code}. Output:\n{install_output}")
                raise RuntimeError(
                    f"Dependency installation failed with code {install_res.exit_code}.\nOutput:\n{install_output}"
                )

            logger.info("Disconnecting networks...")
            container.reload()
            networks = container.attrs.get("NetworkSettings", {}).get("Networks", {})
            for net_name in list(networks.keys()):
                try:
                    network = client.networks.get(net_name)
                    network.disconnect(container)
                except Exception as e:
                    logger.warning(f"Failed to disconnect network {net_name}: {e}")

            logger.info("Running pytest inside container...")
            test_res = container.exec_run(
                "bash -c 'cd repo && python -m pytest --tb=short'"
            )
            exit_code = test_res.exit_code
            stdout_stderr = test_res.output.decode("utf-8", errors="replace")
            logger.info(f"Pytest exited with code {exit_code}")

            if exit_code == 1:
                reproduced = True

            for line in stdout_stderr.splitlines():
                if line.startswith("FAILED "):
                    parts = line.split()
                    if len(parts) >= 2:
                        test_id = parts[1]
                        failing_tests.append(test_id)

            traceback_str = stdout_stderr

        except Exception as e:
            traceback_str = f"Error during reproduction: {e}\n{traceback_str}"
            logger.exception("Exception inside container execution block")
        finally:
            if container:
                try:
                    logger.info("Stopping and removing container...")
                    container.stop()
                    container.remove()
                except Exception as e:
                    logger.warning(f"Failed to destroy container: {e}")

        result = ReproductionResult(
            reproduced=reproduced,
            failing_tests=failing_tests,
            traceback=traceback_str,
            reproduction_command=reproduction_command,
        )

        state_delta = {
            "reproduced": reproduced,
            "failing_tests": failing_tests,
            "reproducer_traceback": traceback_str,
            "reproduction_command": reproduction_command,
        }

        return Event(output=result, actions={"state_delta": state_delta})

    except Exception as e:
        tb_str = traceback.format_exc()
        logger.error(f"Critical error in reproduce_bug node: {e}\n{tb_str}")
        result = ReproductionResult(
            reproduced=False,
            failing_tests=[],
            traceback=f"Critical error in reproduce_bug node: {e}\n{tb_str}",
            reproduction_command="pytest --tb=short",
        )
        state_delta = {
            "reproduced": False,
            "failing_tests": [],
            "reproducer_traceback": f"Critical error in reproduce_bug node: {e}\n{tb_str}",
            "reproduction_command": "pytest --tb=short",
        }
        return Event(output=result, actions={"state_delta": state_delta})


def prepare_root_cause_input(ctx: Context, node_input: ReproductionResult) -> str:
    """Formats the prompt for the analyze_root_cause LlmAgent."""
    repo_full_name = ctx.state.get("repo_full_name", "")
    issue_number = ctx.state.get("issue_number", "")
    title = ctx.state.get("title", "")
    sanitized_body = ctx.state.get("sanitized_body", "")

    owner, repo = "", ""
    if "/" in repo_full_name:
        owner, repo = repo_full_name.split("/", 1)

    reproduced_str = "Yes" if node_input.reproduced else "No"
    failing_tests_str = (
        ", ".join(node_input.failing_tests) if node_input.failing_tests else "None"
    )

    prompt = f"""We are triaging and debugging the following GitHub Issue:
Repository: {repo_full_name} (Owner: '{owner}', Repo: '{repo}')
Issue Number: {issue_number}
Title: {title}

Issue Description:
{sanitized_body}

Reproduction Results:
- Reproduced: {reproduced_str}
- Failing Tests: {failing_tests_str}
- Execution output/traceback:
{node_input.traceback}

Your task is to analyze the root cause of this bug.
Use the 'get_file_contents' tool to retrieve the contents of the files mentioned in the traceback (or related files in the repository).
Remember:
1. Provide the exact owner ('{owner}') and repo ('{repo}') arguments to the tool.
2. Fetch ONLY the files that are relevant to the traceback. Do NOT retrieve the whole repository.
Once you have retrieved the file contents and analyzed the bug, provide:
1. An explanation of the root cause.
2. The list of files that need to be modified (as a list of file paths relative to the repository root).
"""
    return prompt


analyze_root_cause = LlmAgent(
    name="analyze_root_cause",
    model=CONFIG["MODEL_NAME"],
    instruction="""You are an expert software developer.
Analyze the provided issue, reproduction result, and traceback.
Use the 'get_file_contents' tool to fetch files mentioned in the traceback.
Identify the root cause of the bug and determine which files need to be modified to fix the issue.
Conform exactly to the requested output schema.
""",
    tools=[github_mcp],
    output_schema=RootCauseOutput,
)


def fetch_files_for_fix(ctx: Context, node_input: RootCauseOutput) -> Event:
    """Helper node that downloads the files to modify using GitHub REST API."""
    repo_full_name = ctx.state.get("repo_full_name", "")
    owner, repo = "", ""
    if "/" in repo_full_name:
        owner, repo = repo_full_name.split("/", 1)

    github_token = os.environ.get("GITHUB_TOKEN", "")
    files_dict = {}
    for path in node_input.files_to_modify:
        try:
            content = fetch_github_file(owner, repo, path, github_token)
            files_dict[path] = content
        except Exception as e:
            files_dict[path] = f"Error fetching file: {e}"

    # Format the prompt for propose_fix
    prompt = f"Root cause explanation:\n{node_input.explanation}\n\nAllowed files to modify: {node_input.files_to_modify}\n\nFile contents:\n"
    for path, content in files_dict.items():
        prompt += f"\n--- File: {path} ---\n{content}\n"

    prompt += "\nPlease propose a fix as a unified diff that ONLY modifies the allowed files. Do not modify any other files."

    state_delta = {
        "explanation": node_input.explanation,
        "files_to_modify": node_input.files_to_modify,
        "file_contents": files_dict,
    }
    return Event(output=prompt, actions={"state_delta": state_delta})


propose_fix = LlmAgent(
    name="propose_fix",
    model=CONFIG["MODEL_NAME"],
    instruction="""You are a senior software engineer.
Propose a code fix for the bug based on the explanation and file contents.
Output a unified diff of the changes. The diff must ONLY modify the files specified in the allowed files list.
Do not modify any other files.
Conform exactly to the requested output schema.
""",
    output_schema=FixProposal,
)


def validate_diff(ctx: Context, node_input: FixProposal) -> Event:
    """Validates that the diff only modifies files in files_to_modify."""
    diff_str = node_input.diff
    modified_files = get_modified_files(diff_str)
    allowed_files = ctx.state.get("files_to_modify", [])

    if not modified_files:
        error_msg = "Validation failed: No modified files found in the diff or the diff format is invalid. Please make sure to output a valid unified diff."
        return _handle_retry_or_fail(ctx, error_msg)

    for file in modified_files:
        if file not in allowed_files:
            error_msg = f"Validation failed: The diff modifies file '{file}', which is not in the allowed list of files to modify: {allowed_files}. Please ensure you only modify the allowed files."
            return _handle_retry_or_fail(ctx, error_msg)

    state_delta = {
        "proposed_diff": diff_str,
        "fix_explanation": node_input.explanation,
        "validation_status": "success",
    }
    return Event(
        output="Diff validated successfully.",
        actions={"route": "success", "state_delta": state_delta},
    )


def _handle_retry_or_fail(ctx: Context, error_msg: str) -> Event:
    retries = ctx.state.get("validation_retries", 0)
    if retries < 3:
        new_retries = retries + 1
        state_delta = {"validation_retries": new_retries}
        return Event(
            output=error_msg, actions={"route": "retry", "state_delta": state_delta}
        )
    else:
        state_delta = {"validation_status": "fail", "validation_error": error_msg}
        return Event(
            output=f"Validation failed after 3 retries: {error_msg}",
            actions={"route": "fail", "state_delta": state_delta},
        )


# --- Non-Bug Pipeline Nodes ---


def prepare_non_bug_input(ctx: Context, node_input: ClassificationOutput) -> str:
    """Formats the prompt for the handle_non_bug LlmAgent."""
    repo_full_name = ctx.state.get("repo_full_name", "")
    issue_number = ctx.state.get("issue_number", "")
    title = ctx.state.get("title", "")
    sanitized_body = ctx.state.get("sanitized_body", "")

    owner, repo = "", ""
    if "/" in repo_full_name:
        owner, repo = repo_full_name.split("/", 1)

    prompt = f"""We are handling a non-bug GitHub Issue:
Repository: {repo_full_name} (Owner: '{owner}', Repo: '{repo}')
Issue Number: {issue_number}
Title: {title}
Classification: {node_input.classification}
Severity: {node_input.severity}

Issue Description:
{sanitized_body}

Please handle this issue:
1. Add the classification '{node_input.classification}' (or another appropriate label) to this issue using the 'add_label_to_issue' tool.
   Use the exact owner ('{owner}') and repo ('{repo}') arguments.
2. Comment on this issue using 'create_issue_comment' explaining how it is classified and next steps.
   Use the exact owner ('{owner}') and repo ('{repo}') arguments.
"""
    return prompt


handle_non_bug = LlmAgent(
    name="handle_non_bug",
    model=CONFIG["MODEL_NAME"],
    instruction="""You are an AI assistant helping to maintain a GitHub repository.
You are handling a non-bug issue. Based on the issue details and classification:
1. Choose an appropriate label (like 'docs', 'feature', etc.) and add it to the issue using the 'add_label_to_issue' tool.
2. Add a helpful comment explaining that the issue has been classified as a non-bug and what the next steps are, using the 'create_issue_comment' tool.
Conform exactly to the requested output schema.
""",
    tools=[github_mcp],
    output_schema=NonBugOutput,
)


async def security_audit(ctx: Context, node_input: Any) -> Event:
    """Runs a Semgrep security audit on the proposed diff before human approval."""
    import json
    import logging
    import re
    logger = logging.getLogger("autopatch.security_audit")

    diff_str = ctx.state.get("proposed_diff", "")
    if not diff_str:
        logger.warning("No proposed diff found in state to audit.")
        return Event(
            output="No diff to audit.",
            actions={"state_delta": {"security_findings": [], "security_status": "clean"}}
        )

    logger.info("Initializing Semgrep MCP and fetching tools...")
    try:
        tools = await semgrep_mcp.get_tools()
        scan_diff_tool = next((t for t in tools if t.name == "scan_diff"), None)
        if not scan_diff_tool:
            raise RuntimeError("Semgrep MCP tool 'scan_diff' not found.")

        custom_rule = {
            "id": "detect-google-api-key",
            "pattern-regex": "AIzaSy[A-Za-z0-9_-]*",
            "message": "Hardcoded Google API key prefix detected",
            "severity": "ERROR",
            "languages": ["generic"]
        }

        decl = scan_diff_tool._get_declaration()
        param_names = list(decl.parameters.properties.keys()) if decl and decl.parameters else []

        args = {}
        if "diff" in param_names:
            args["diff"] = diff_str
        elif "git_diff" in param_names:
            args["git_diff"] = diff_str
        elif "diff_content" in param_names:
            args["diff_content"] = diff_str
        else:
            args[param_names[0] if param_names else "diff"] = diff_str

        if "rules" in param_names:
            args["rules"] = [custom_rule, "owasp-top-10"]
        elif "config" in param_names:
            args["config"] = [custom_rule, "owasp-top-10"]
        else:
            args["rules"] = [custom_rule, "owasp-top-10"]

        logger.info(f"Calling scan_diff tool with parameters: {list(args.keys())}")
        result = await scan_diff_tool.run_async(args=args, tool_context=ctx)

        findings = []
        has_critical = False
        has_warning = False
        raw_text = ""

        if isinstance(result, dict):
            content_list = result.get("content", [])
            for block in content_list:
                if block.get("type") == "text" and block.get("text"):
                    text = block["text"]
                    raw_text += text + "\n"
                    try:
                        parsed = json.loads(text)
                        if isinstance(parsed, list):
                            findings.extend(parsed)
                        elif isinstance(parsed, dict):
                            if "findings" in parsed:
                                findings.extend(parsed["findings"])
                            else:
                                findings.append(parsed)
                    except Exception:
                        pass

        for f in findings:
            severity = str(f.get("severity", "")).upper()
            if severity in ("CRITICAL", "ERROR"):
                has_critical = True
            elif severity == "WARNING":
                has_warning = True

        if "CRITICAL" in raw_text.upper() or "ERROR" in raw_text.upper() or "AIZASY" in raw_text.upper():
            has_critical = True
        elif "WARNING" in raw_text.upper():
            has_warning = True

        logger.info(f"Security audit complete. Critical={has_critical}, Warning={has_warning}")

        if has_critical:
            state_delta = {
                "security_event": True,
                "security_findings": findings if findings else raw_text,
                "security_status": "critical"
            }
            return Event(
                output=f"🚨 SECURITY AUDIT FAILED (CRITICAL):\n{raw_text or findings}",
                actions={"state_delta": state_delta}
            )
        elif has_warning:
            state_delta = {
                "security_findings": findings if findings else raw_text,
                "security_status": "warning"
            }
            return Event(
                output=f"⚠️ SECURITY AUDIT WARNING:\n{raw_text or findings}",
                actions={"state_delta": state_delta}
            )
        else:
            state_delta = {
                "security_findings": [],
                "security_status": "clean"
            }
            return Event(
                output="✅ Security audit clean. No issues found.",
                actions={"state_delta": state_delta}
            )

    except Exception as e:
        logger.error(f"Error during security audit: {e}", exc_info=True)
        # Fallback check
        api_key_regex = re.compile(r"AIzaSy[A-Za-z0-9_-]*")
        matches = api_key_regex.findall(diff_str)
        if matches:
            state_delta = {
                "security_event": True,
                "security_findings": [f"Fallback regex matched API key prefix: {matches}"],
                "security_status": "critical"
            }
            return Event(
                output=f"🚨 SECURITY AUDIT FAILED (CRITICAL - Fallback Check):\nFound hardcoded Google API key prefixes: {matches}",
                actions={"state_delta": state_delta}
            )
        else:
            state_delta = {
                "security_findings": [f"Security audit error: {e}"],
                "security_status": "error"
            }
            return Event(
                output=f"⚠️ Security audit errored out: {e}. Pass through as clean.",
                actions={"state_delta": state_delta}
            )


def parse_multi_file_diff(diff_str: str) -> dict[str, str]:
    """Parses a multi-file unified diff into a dict mapping file path to the diff of that file."""
    file_diffs = {}
    current_file = None
    current_lines = []

    for line in diff_str.splitlines():
        if line.startswith('--- a/') or line.startswith('--- '):
            if current_file and current_lines:
                file_diffs[current_file] = '\n'.join(current_lines)
            if line.startswith('--- a/'):
                current_file = line[6:]
            else:
                current_file = line[4:]
            current_file = current_file.split('\t')[0].strip()
            current_lines = [line]
        elif line.startswith('+++ b/') or line.startswith('+++ '):
            if current_file:
                current_lines.append(line)
        elif current_file is not None:
            current_lines.append(line)

    if current_file and current_lines:
        file_diffs[current_file] = '\n'.join(current_lines)

    return file_diffs


def apply_patch(original_content: str, patch_str: str) -> str:
    """Applies a unified diff patch to the original content string."""
    lines = original_content.splitlines(keepends=True)
    patch_lines = patch_str.splitlines()

    hunks = []
    current_hunk = None

    i = 0
    while i < len(patch_lines):
        line = patch_lines[i]
        if line.startswith('@@'):
            parts = line.split()
            old_part = parts[1]
            new_part = parts[2]

            old_start = int(old_part[1:].split(',')[0])
            new_start = int(new_part[1:].split(',')[0])

            current_hunk = {
                'old_start': old_start,
                'new_start': new_start,
                'lines': []
            }
            hunks.append(current_hunk)
        elif current_hunk is not None:
            if line.startswith('\\'):
                pass
            else:
                current_hunk['lines'].append(line)
        i += 1

    hunks.sort(key=lambda h: h['old_start'], reverse=True)

    for hunk in hunks:
        old_start = hunk['old_start']
        hunk_lines = hunk['lines']

        expected_old = []
        new_lines_to_insert = []

        for hl in hunk_lines:
            if hl.startswith(' '):
                expected_old.append(hl[1:])
                new_lines_to_insert.append(hl[1:])
            elif hl.startswith('-'):
                expected_old.append(hl[1:])
            elif hl.startswith('+'):
                new_lines_to_insert.append(hl[1:])

        start_idx = old_start - 1
        matched_idx = -1

        search_radius = 200
        for offset in range(search_radius):
            for sign in [1, -1] if offset > 0 else [1]:
                idx = start_idx + sign * offset
                if 0 <= idx <= len(lines) - len(expected_old):
                    match = True
                    for j, exp in enumerate(expected_old):
                        actual = lines[idx + j].rstrip('\r\n')
                        if actual != exp.rstrip('\r\n'):
                            match = False
                            break
                    if match:
                        matched_idx = idx
                        break
            if matched_idx != -1:
                break

        if matched_idx == -1:
            matched_idx = max(0, min(start_idx, len(lines)))

        replacement = []
        for nl in new_lines_to_insert:
            replacement.append(nl + '\n')

        lines[matched_idx : matched_idx + len(expected_old)] = replacement

    return "".join(lines)


async def get_default_branch_and_sha(ctx: Context, owner: str, repo: str) -> tuple[str, str]:
    """Returns (default_branch_name, latest_sha)."""
    import json
    import os
    import requests
    import logging
    logger = logging.getLogger("autopatch.open_pr.get_default_branch")

    try:
        tools = await github_mcp.get_tools()
        get_repo_tool = next((t for t in tools if "get_repository" in t.name or "get_repo" in t.name), None)
        if get_repo_tool:
            args = {"owner": owner, "repo": repo}
            result = await get_repo_tool.run_async(args=args, tool_context=ctx)
            default_branch = ""
            if isinstance(result, dict):
                for block in result.get("content", []):
                    if block.get("type") == "text" and block.get("text"):
                        try:
                            data = json.loads(block["text"])
                            if isinstance(data, dict):
                                default_branch = data.get("default_branch", "")
                        except Exception:
                            pass

            if default_branch:
                get_branch_tool = next((t for t in tools if "get_branch" in t.name or "get_ref" in t.name), None)
                if get_branch_tool:
                    decl = get_branch_tool._get_declaration()
                    param_names = list(decl.parameters.properties.keys()) if decl and decl.parameters else []
                    args = {"owner": owner, "repo": repo}
                    if "branch" in param_names:
                        args["branch"] = default_branch
                    elif "ref" in param_names:
                        args["ref"] = f"heads/{default_branch}"

                    branch_result = await get_branch_tool.run_async(args=args, tool_context=ctx)
                    sha = ""
                    if isinstance(branch_result, dict):
                        for block in branch_result.get("content", []):
                            if block.get("type") == "text" and block.get("text"):
                                try:
                                    b_data = json.loads(block["text"])
                                    if isinstance(b_data, dict):
                                        if "commit" in b_data:
                                            sha = b_data["commit"].get("sha", "")
                                        elif "object" in b_data:
                                            sha = b_data["object"].get("sha", "")
                                        elif "sha" in b_data:
                                            sha = b_data.get("sha", "")
                                except Exception:
                                    pass
                    if sha:
                        return default_branch, sha
    except Exception as e:
        logger.warning(f"Failed to get default branch via MCP: {e}. Trying REST API...")

    github_token = os.environ.get("GITHUB_TOKEN", "")
    headers = {
        "Authorization": f"Bearer {github_token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28"
    }
    repo_url = f"https://api.github.com/repos/{owner}/{repo}"
    resp = requests.get(repo_url, headers=headers)
    if resp.status_code == 200:
        repo_data = resp.json()
        default_branch = repo_data.get("default_branch", "main")

        branch_url = f"https://api.github.com/repos/{owner}/{repo}/git/ref/heads/{default_branch}"
        branch_resp = requests.get(branch_url, headers=headers)
        if branch_resp.status_code == 200:
            branch_data = branch_resp.json()
            sha = branch_data.get("object", {}).get("sha", "")
            return default_branch, sha

    raise RuntimeError("Failed to retrieve default branch and latest commit SHA.")


async def create_branch_via_mcp_or_api(ctx: Context, owner: str, repo: str, branch_name: str, sha: str):
    """Creates a new branch on GitHub from the specified commit SHA."""
    import os
    import requests
    import logging
    logger = logging.getLogger("autopatch.open_pr.create_branch")
    ref_name = f"refs/heads/{branch_name}"
    try:
        tools = await github_mcp.get_tools()
        create_ref_tool = next((t for t in tools if "create_ref" in t.name or "create_branch" in t.name or "create_reference" in t.name), None)
        if create_ref_tool:
            decl = create_ref_tool._get_declaration()
            param_names = list(decl.parameters.properties.keys()) if decl and decl.parameters else []
            args = {"owner": owner, "repo": repo, "sha": sha}
            if "ref" in param_names:
                args["ref"] = ref_name
            elif "branch" in param_names:
                args["branch"] = branch_name
            elif "name" in param_names:
                args["name"] = branch_name

            await create_ref_tool.run_async(args=args, tool_context=ctx)
            logger.info(f"Branch '{branch_name}' created via MCP.")
            return
    except Exception as e:
        logger.warning(f"Failed to create branch via MCP: {e}. Trying REST API...")

    github_token = os.environ.get("GITHUB_TOKEN", "")
    url = f"https://api.github.com/repos/{owner}/{repo}/git/refs"
    headers = {
        "Authorization": f"Bearer {github_token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28"
    }
    data = {
        "ref": ref_name,
        "sha": sha
    }
    resp = requests.post(url, headers=headers, json=data)
    if resp.status_code in (201, 200):
        logger.info(f"Branch '{branch_name}' created via REST API.")
    elif resp.status_code == 422 and "already exists" in resp.text:
        logger.info(f"Branch '{branch_name}' already exists.")
    else:
        raise RuntimeError(f"Failed to create branch '{branch_name}': {resp.status_code} - {resp.text}")


async def fetch_file_content_via_mcp_or_api(ctx: Context, owner: str, repo: str, path: str, ref: str) -> tuple[str, str]:
    """Fetches original file content and its blob SHA. Returns (content, sha)."""
    import os
    import requests
    import base64
    import json
    import logging
    logger = logging.getLogger("autopatch.open_pr.fetch_file_content")

    try:
        tools = await github_mcp.get_tools()
        get_file_tool = next((t for t in tools if "get_file" in t.name or "get_contents" in t.name), None)
        if get_file_tool:
            decl = get_file_tool._get_declaration()
            param_names = list(decl.parameters.properties.keys()) if decl and decl.parameters else []
            args = {"owner": owner, "repo": repo, "path": path}
            if "ref" in param_names:
                args["ref"] = ref
            elif "branch" in param_names:
                args["branch"] = ref

            result = await get_file_tool.run_async(args=args, tool_context=ctx)
            content_str = ""
            sha = ""
            if isinstance(result, dict):
                for block in result.get("content", []):
                    if block.get("type") == "text" and block.get("text"):
                        try:
                            data = json.loads(block["text"])
                            if isinstance(data, dict):
                                sha = data.get("sha", "")
                                raw_content = data.get("content", "")
                                encoding = data.get("encoding", "")
                                if encoding == "base64":
                                    content_str = base64.b64decode(raw_content).decode("utf-8")
                                else:
                                    content_str = raw_content
                        except Exception:
                            pass
            if content_str:
                return content_str, sha
    except Exception as e:
        logger.warning(f"Failed to get file contents via MCP: {e}. Trying REST API...")

    github_token = os.environ.get("GITHUB_TOKEN", "")
    url = f"https://api.github.com/repos/{owner}/{repo}/contents/{path}"
    headers = {
        "Authorization": f"Bearer {github_token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28"
    }
    params = {"ref": ref}
    resp = requests.get(url, headers=headers, params=params)
    if resp.status_code == 200:
        data = resp.json()
        sha = data.get("sha", "")
        raw_content = data.get("content", "")
        encoding = data.get("encoding", "")
        if encoding == "base64":
            content_str = base64.b64decode(raw_content).decode("utf-8")
        else:
            content_str = raw_content
        return content_str, sha
    else:
        raise RuntimeError(f"Failed to fetch file contents for {path}: {resp.status_code} - {resp.text}")


async def commit_file_change_via_mcp_or_api(
    ctx: Context, owner: str, repo: str, path: str, content: str, sha: str, branch_name: str, commit_msg: str
):
    """Commits a file update to the specified branch."""
    import os
    import requests
    import base64
    import logging
    logger = logging.getLogger("autopatch.open_pr.commit_file_change")

    try:
        tools = await github_mcp.get_tools()
        update_file_tool = next(
            (t for t in tools if "update_file" in t.name or "create_or_update_file" in t.name or "commit" in t.name),
            None
        )
        if update_file_tool:
            decl = update_file_tool._get_declaration()
            param_names = list(decl.parameters.properties.keys()) if decl and decl.parameters else []
            args = {
                "owner": owner,
                "repo": repo,
                "path": path,
                "content": content,
                "message": commit_msg,
                "sha": sha
            }
            if "branch" in param_names:
                args["branch"] = branch_name
            elif "ref" in param_names:
                args["ref"] = branch_name

            await update_file_tool.run_async(args=args, tool_context=ctx)
            logger.info(f"Committed '{path}' to branch '{branch_name}' via MCP.")
            return
    except Exception as e:
        logger.warning(f"Failed to commit '{path}' via MCP: {e}. Trying REST API...")

    github_token = os.environ.get("GITHUB_TOKEN", "")
    url = f"https://api.github.com/repos/{owner}/{repo}/contents/{path}"
    headers = {
        "Authorization": f"Bearer {github_token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28"
    }

    encoded_content = base64.b64encode(content.encode("utf-8")).decode("utf-8")

    data = {
        "message": commit_msg,
        "content": encoded_content,
        "branch": branch_name,
        "sha": sha
    }
    resp = requests.put(url, headers=headers, json=data)
    if resp.status_code in (200, 201):
        logger.info(f"Committed '{path}' to branch '{branch_name}' via REST API.")
    else:
        raise RuntimeError(f"Failed to commit '{path}' via REST API: {resp.status_code} - {resp.text}")


async def open_pr(ctx: Context, node_input: Any) -> Event:
    """Creates a branch, commits the patch files, and opens a pull request using GitHub MCP tools or REST API fallback."""
    import logging
    import os
    import requests
    logger = logging.getLogger("autopatch.open_pr")

    repo_full_name = ctx.state.get("repo_full_name", "")
    owner, repo = "", ""
    if "/" in repo_full_name:
        owner, repo = repo_full_name.split("/", 1)

    issue_number = ctx.state.get("issue_number", "")
    root_cause_summary = ctx.state.get("explanation", "")
    explanation = ctx.state.get("fix_explanation", "")
    security_findings = ctx.state.get("security_findings", "")
    diff_str = ctx.state.get("proposed_diff", "")

    branch_name = f"autopatch/issue-{issue_number}"

    # Parse multi-file diff to get patch chunks per file
    file_diffs = parse_multi_file_diff(diff_str)

    # 1. Get default branch name and its latest commit SHA
    default_branch, latest_sha = await get_default_branch_and_sha(ctx, owner, repo)
    logger.info(f"Default branch: {default_branch}, Latest SHA: {latest_sha}")

    # 2. Create the target branch from the latest SHA of the default branch
    await create_branch_via_mcp_or_api(ctx, owner, repo, branch_name, latest_sha)

    # 3. For each file in the diff, fetch current file blob SHA, apply patch, and commit
    for filepath, file_diff in file_diffs.items():
        logger.info(f"Applying patch to {filepath}...")
        try:
            orig_content, file_sha = await fetch_file_content_via_mcp_or_api(ctx, owner, repo, filepath, default_branch)
            patched_content = apply_patch(orig_content, file_diff)
            commit_msg = f"Fix issue #{issue_number}: patch {filepath}"
            await commit_file_change_via_mcp_or_api(ctx, owner, repo, filepath, patched_content, file_sha, branch_name, commit_msg)
        except Exception as e:
            logger.error(f"Error patching file {filepath}: {e}", exc_info=True)
            raise RuntimeError(f"Failed to apply patch to file {filepath}: {e}")

    # 4. Create Pull Request
    pr_body = (
        f"Closes #{issue_number}\n\n"
        f"## Root Cause\n{root_cause_summary}\n\n"
        f"## Changes\n{explanation}\n\n"
        f"## Security Audit\n{security_findings}\n\n"
        f"---\n*Generated by AutoPatch. Reviewed and approved.*"
    )

    output_msg = ""
    try:
        tools = await github_mcp.get_tools()
        pr_tool = next((t for t in tools if "create_pull_request" in t.name or "pull_request" in t.name or "pr" in t.name), None)
        if not pr_tool:
            raise RuntimeError("GitHub MCP tool for creating pull request not found.")

        decl = pr_tool._get_declaration()
        param_names = list(decl.parameters.properties.keys()) if decl and decl.parameters else []

        args = {}
        if "owner" in param_names:
            args["owner"] = owner
        if "repo" in param_names:
            args["repo"] = repo
        if "title" in param_names:
            args["title"] = f"AutoPatch Fix: Issue #{issue_number}"

        if "body" in param_names:
            args["body"] = pr_body
        elif "description" in param_names:
            args["description"] = pr_body

        if "head" in param_names:
            args["head"] = branch_name
        if "base" in param_names:
            args["base"] = default_branch

        result = await pr_tool.run_async(args=args, tool_context=ctx)
        logger.info(f"PR created successfully via MCP: {result}")
        output_msg = f"Pull Request created successfully. Result: {result}"
    except Exception as e:
        logger.error(f"Failed to create PR via MCP: {e}. Attempting fallback via GitHub REST API...")
        github_token = os.environ.get("GITHUB_TOKEN", "")
        if github_token and owner and repo:
            url = f"https://api.github.com/repos/{owner}/{repo}/pulls"
            headers = {
                "Authorization": f"Bearer {github_token}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28"
            }
            data = {
                "title": f"AutoPatch Fix: Issue #{issue_number}",
                "body": pr_body,
                "head": branch_name,
                "base": default_branch
            }
            resp = requests.post(url, headers=headers, json=data)
            if resp.status_code in (200, 201):
                pr_info = resp.json()
                logger.info(f"PR created successfully via fallback: {pr_info.get('html_url')}")
                output_msg = f"Pull Request created successfully via fallback: {pr_info.get('html_url')}"
            else:
                logger.error(f"Fallback PR creation failed: {resp.status_code} - {resp.text}")
                raise RuntimeError(f"Failed to create Pull Request: {resp.text}")
        else:
            raise RuntimeError(f"Failed to create PR via MCP: {e} and fallback not possible.")

    return Event(output=output_msg, actions={"state_delta": {"pull_request_created": True}})


async def close_with_comment(ctx: Context, node_input: Any) -> Event:
    """Closes the issue with a comment explaining the rejection."""
    import logging
    import os
    import requests
    logger = logging.getLogger("autopatch.close_with_comment")

    repo_full_name = ctx.state.get("repo_full_name", "")
    owner, repo = "", ""
    if "/" in repo_full_name:
        owner, repo = repo_full_name.split("/", 1)

    issue_number = ctx.state.get("issue_number", "")
    comment_body = "The proposed fix for this issue was reviewed and rejected by the human reviewer. Re-evaluating or closing task."

    output_msg = ""
    try:
        tools = await github_mcp.get_tools()
        comment_tool = next((t for t in tools if "create_issue_comment" in t.name or "create_comment" in t.name or "comment" in t.name), None)
        if not comment_tool:
            raise RuntimeError("GitHub MCP tool for creating comment not found.")

        decl = comment_tool._get_declaration()
        param_names = list(decl.parameters.properties.keys()) if decl and decl.parameters else []

        args = {}
        if "owner" in param_names:
            args["owner"] = owner
        if "repo" in param_names:
            args["repo"] = repo
        if "issue_number" in param_names:
            args["issue_number"] = issue_number
        elif "number" in param_names:
            args["number"] = issue_number
        elif "issue" in param_names:
            args["issue"] = issue_number

        if "body" in param_names:
            args["body"] = comment_body
        elif "text" in param_names:
            args["text"] = comment_body

        result = await comment_tool.run_async(args=args, tool_context=ctx)
        logger.info(f"Rejection comment posted via MCP: {result}")
        output_msg = f"Rejection comment posted successfully. Result: {result}"
    except Exception as e:
        logger.error(f"Failed to post comment via MCP: {e}. Attempting fallback via GitHub REST API...")
        github_token = os.environ.get("GITHUB_TOKEN", "")
        if github_token and owner and repo:
            url = f"https://api.github.com/repos/{owner}/{repo}/issues/{issue_number}/comments"
            headers = {
                "Authorization": f"Bearer {github_token}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28"
            }
            data = {"body": comment_body}
            resp = requests.post(url, headers=headers, json=data)
            if resp.status_code in (200, 201):
                logger.info("Rejection comment posted via fallback REST API.")
                output_msg = "Rejection comment posted successfully via fallback."
            else:
                logger.error(f"Fallback comment posting failed: {resp.status_code} - {resp.text}")
                raise RuntimeError(f"Failed to post comment: {resp.text}")
        else:
            raise RuntimeError(f"Failed to post comment via MCP: {e} and fallback not possible.")

    # Also close the issue
    try:
        github_token = os.environ.get("GITHUB_TOKEN", "")
        if github_token and owner and repo:
            url = f"https://api.github.com/repos/{owner}/{repo}/issues/{issue_number}"
            headers = {
                "Authorization": f"Bearer {github_token}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28"
            }
            data = {"state": "closed"}
            resp = requests.patch(url, headers=headers, json=data)
            if resp.status_code in (200, 201):
                logger.info("Issue closed successfully via REST API.")
            else:
                logger.warning(f"Failed to close issue via REST API: {resp.status_code} - {resp.text}")
    except Exception as ex:
        logger.warning(f"Error trying to close issue: {ex}")

    return Event(output=output_msg, actions={"state_delta": {"rejection_comment_posted": True}})


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
        # 5. Route to appropriate pipeline or HITL
        (
            route_issue,
            {
                "bug_pipeline": reproduce_bug,
                "hitl_direct": human_approval,
                "non_bug": prepare_non_bug_input,
            },
        ),
        # Bug Pipeline branch
        (reproduce_bug, prepare_root_cause_input),
        (prepare_root_cause_input, analyze_root_cause),
        (analyze_root_cause, fetch_files_for_fix),
        (fetch_files_for_fix, propose_fix),
        (propose_fix, validate_diff),
        # Diff Validation Retry / Success / Fail Loops
        (
            validate_diff,
            {
                "retry": propose_fix,
                "success": security_audit,
                "__DEFAULT__": human_approval,
            },
        ),
        (security_audit, human_approval),
        # HITL Resolution routing
        (
            human_approval,
            {
                "approve": open_pr,
                "reject": close_with_comment,
            }
        ),
        # Non-Bug Pipeline branch
        (prepare_non_bug_input, handle_non_bug),
        (handle_non_bug, human_approval),
    ],
)

app = App(
    root_agent=root_agent,
    name="autopatch",
)
