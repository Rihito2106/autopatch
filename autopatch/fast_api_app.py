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
import base64
import json
import logging
import os
from typing import Any
import uuid

from fastapi import BackgroundTasks, FastAPI, Request
from google.adk.cli.fast_api import get_fast_api_app
from google.adk.runners import Runner
from google.adk.sessions import InMemorySessionService
from google.genai import types

from autopatch.agent import root_agent
from autopatch.app_utils.telemetry import setup_telemetry
from autopatch.app_utils.typing import Feedback

# Configure standard Python logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

setup_telemetry()
allow_origins = (
    os.getenv("ALLOW_ORIGINS", "").split(",") if os.getenv("ALLOW_ORIGINS") else None
)

# Artifact bucket for ADK (created by Terraform, passed via env var)
logs_bucket_name = os.environ.get("LOGS_BUCKET_NAME")

AGENT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
# In-memory session configuration - no persistent storage
session_service_uri = None

artifact_service_uri = f"gs://{logs_bucket_name}" if logs_bucket_name else None

app: FastAPI = get_fast_api_app(
    agents_dir=AGENT_DIR,
    web=True,
    artifact_service_uri=artifact_service_uri,
    allow_origins=allow_origins,
    session_service_uri=session_service_uri,
    otel_to_cloud=False,
)
app.title = "autopatch"
app.description = "API for interacting with the Agent autopatch"

# Initialize runner for ambient workflow execution
session_service = InMemorySessionService()
runner = Runner(
    agent=root_agent,
    session_service=session_service,
    app_name="autopatch",
    auto_create_session=True,
)


def normalize_webhook_payload(payload: Any) -> Any:
    """Normalizes GitHub webhook payload.

    If the payload is a dictionary containing a 'data' key,
    it extracts the value, decodes it if it is base64-encoded,
    and returns the normalized payload.
    """
    if isinstance(payload, dict) and "data" in payload:
        inner = payload["data"]
        if isinstance(inner, str):
            try:
                decoded_bytes = base64.b64decode(inner.strip(), validate=True)
                decoded_str = decoded_bytes.decode("utf-8")
                try:
                    return json.loads(decoded_str)
                except json.JSONDecodeError:
                    return decoded_str
            except Exception:
                try:
                    return json.loads(inner)
                except json.JSONDecodeError:
                    return inner
        return inner
    return payload


async def run_workflow_task(payload: Any):
    logger.info("Starting AutoPatch ADK workflow run from webhook event.")
    try:
        normalized_payload = normalize_webhook_payload(payload)

        # Extract metadata to create a descriptive session_id
        repo_name = None
        issue_num = None
        if isinstance(normalized_payload, dict):
            repo_name = normalized_payload.get("repo_full_name")
            if not repo_name:
                repo_dict = normalized_payload.get("repository")
                if isinstance(repo_dict, dict):
                    repo_name = repo_dict.get("full_name")

            issue_num = normalized_payload.get("issue_number")
            if issue_num is None:
                issue_dict = normalized_payload.get("issue")
                if isinstance(issue_dict, dict):
                    issue_num = issue_dict.get("number")

        if repo_name and issue_num:
            clean_repo = str(repo_name).replace("/", "-")
            session_id = f"session-{clean_repo}-{issue_num}"
        else:
            session_id = f"session-{uuid.uuid4()}"

        user_id = "github-webhook"

        # Prepare the message content for ADK workflow with structured dictionary payload
        message = types.Content(
            role="user",
            parts=[
                types.Part(
                    function_response=types.FunctionResponse(
                        name="webhook_event",
                        response=normalized_payload,
                    )
                )
            ],
        )

        logger.info(f"Running ADK workflow for session_id: {session_id}, user_id: {user_id}")

        async for event in runner.run_async(
            user_id=user_id,
            session_id=session_id,
            new_message=message,
        ):
            logger.info(f"[{session_id}] Event: {event.author} - {event.output if event.output else ''}")

        logger.info(f"ADK workflow for session_id: {session_id} finished successfully.")
    except Exception as e:
        logger.exception(f"Error running ADK workflow: {e}")


@app.post("/webhook")
async def receive_webhook(request: Request, background_tasks: BackgroundTasks):
    try:
        payload = await request.json()
    except Exception as e:
        logger.error(f"Failed to parse incoming request JSON: {e}")
        return {"status": "error", "message": "Invalid JSON body"}

    background_tasks.add_task(run_workflow_task, payload)
    return {"status": "accepted"}


@app.get("/health")
def health_check():
    return {"status": "ok"}


@app.post("/feedback")
def collect_feedback(feedback: Feedback) -> dict[str, str]:
    """Collect and log feedback.

    Args:
        feedback: The feedback data to log

    Returns:
        Success message
    """
    logger.info(f"Feedback collected: {feedback.model_dump()}")
    return {"status": "success"}


# Main execution
if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8080)
