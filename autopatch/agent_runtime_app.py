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
import logging
import os
from typing import Any, Optional, List, Union, Generator, AsyncIterable

import vertexai
from dotenv import load_dotenv
from google.adk.artifacts import GcsArtifactService, InMemoryArtifactService
from google.cloud import logging as google_cloud_logging
from vertexai.agent_engines.templates.adk import AdkApp

from autopatch.agent import app as adk_app
from autopatch.app_utils.telemetry import setup_telemetry
from autopatch.app_utils.typing import Feedback

# Load environment variables from .env file at runtime
load_dotenv()


class AgentEngineApp(AdkApp):
    def set_up(self) -> None:
        """Initialize the agent engine app with logging and telemetry."""
        vertexai.init()
        setup_telemetry()
        super().set_up()
        logging.basicConfig(level=logging.INFO)
        logging_client = google_cloud_logging.Client()
        self.logger = logging_client.logger(__name__)
        if gemini_location:
            os.environ["GOOGLE_CLOUD_LOCATION"] = gemini_location

    def register_feedback(self, feedback: dict[str, Any]) -> None:
        """Collect and log feedback."""
        feedback_obj = Feedback.model_validate(feedback)
        self.logger.log_struct(feedback_obj.model_dump(), severity="INFO")

    def register_operations(self) -> dict[str, list[str]]:
        """Registers the operations of the Agent."""
        operations = super().register_operations()
        operations[""] = [*operations.get("", []), "register_feedback"]
        return operations

    def clone(self) -> "AgentEngineApp":
        """Returns a clone of the Agent Runtime application."""
        return self

    async def async_stream_query(
        self,
        *,
        message: Union[str, dict[str, Any]],
        user_id: str = "default-user",
        session_id: Optional[str] = None,
        session_events: Optional[List[dict[str, Any]]] = None,
        run_config: Optional[dict[str, Any]] = None,
        **kwargs,
    ) -> AsyncIterable[dict[str, Any]]:
        """Streams responses asynchronously, forcing user_id='default-user'."""
        user_id = "default-user"
        async for event in super().async_stream_query(
            message=message,
            user_id=user_id,
            session_id=session_id,
            session_events=session_events,
            run_config=run_config,
            **kwargs,
        ):
            yield event

    def stream_query(
        self,
        *,
        message: Union[str, dict[str, Any]],
        user_id: str = "default-user",
        session_id: Optional[str] = None,
        run_config: Optional[dict[str, Any]] = None,
        **kwargs,
    ) -> Generator[dict[str, Any], None, None]:
        """Streams responses synchronously, forcing user_id='default-user'."""
        user_id = "default-user"
        for event in super().stream_query(
            message=message,
            user_id=user_id,
            session_id=session_id,
            run_config=run_config,
            **kwargs,
        ):
            yield event

    async def async_create_session(
        self,
        *,
        user_id: str = "default-user",
        **kwargs,
    ) -> dict[str, Any]:
        user_id = "default-user"
        return await super().async_create_session(user_id=user_id, **kwargs)

    def create_session(
        self,
        *,
        user_id: str = "default-user",
        **kwargs,
    ) -> dict[str, Any]:
        user_id = "default-user"
        return super().create_session(user_id=user_id, **kwargs)

    async def async_get_session(
        self,
        *,
        user_id: str = "default-user",
        session_id: str,
        **kwargs,
    ) -> dict[str, Any]:
        user_id = "default-user"
        return await super().async_get_session(user_id=user_id, session_id=session_id, **kwargs)

    def get_session(
        self,
        *,
        user_id: str = "default-user",
        session_id: str,
        **kwargs,
    ) -> dict[str, Any]:
        user_id = "default-user"
        return super().get_session(user_id=user_id, session_id=session_id, **kwargs)

    async def async_delete_session(
        self,
        *,
        user_id: str = "default-user",
        session_id: str,
        **kwargs,
    ):
        user_id = "default-user"
        await super().async_delete_session(user_id=user_id, session_id=session_id, **kwargs)

    def delete_session(
        self,
        *,
        user_id: str = "default-user",
        session_id: str,
        **kwargs,
    ):
        user_id = "default-user"
        super().delete_session(user_id=user_id, session_id=session_id, **kwargs)


gemini_location = os.environ.get("GOOGLE_CLOUD_LOCATION")
logs_bucket_name = os.environ.get("LOGS_BUCKET_NAME")
agent_runtime = AgentEngineApp(
    app=adk_app,
    artifact_service_builder=lambda: (
        GcsArtifactService(bucket_name=logs_bucket_name)
        if logs_bucket_name
        else InMemoryArtifactService()
    ),
)
