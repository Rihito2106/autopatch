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
from google.adk.tools.mcp_tool.mcp_session_manager import SseConnectionParams

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


# --- GitHub MCP Toolset Configuration ---


github_mcp = McpToolset(
    connection_params=SseConnectionParams(
        url="https://api.githubcopilot.com/mcp/",
    ),
    header_provider=lambda ctx=None: {
        "Authorization": f"Bearer {os.environ.get('GITHUB_TOKEN', '')}"
    },
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
                "__DEFAULT__": human_approval,
            },
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
