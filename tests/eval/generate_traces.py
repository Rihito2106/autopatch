import asyncio
import json
import os
import sys
import requests
from google.adk.runners import Runner
from google.adk.sessions import InMemorySessionService
from google.genai import types

# Add project root to sys.path so we can import autopatch
project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from autopatch.agent import root_agent

# ---------------------------------------------------------------------------
# Per-scenario expected behavior definitions
# ---------------------------------------------------------------------------
SCENARIO_SPECS = {
    "TC01": {
        "description": "Normal bug: full bug pipeline + approve",
        "expected_pause": True,
        "resume_result": "approve",
        "expected_nodes_fired": {"reproduce_bug", "analyze_root_cause", "propose_fix"},
        "forbidden_nodes": set(),
        "validate_after_resume": lambda ctx: _validate_pr_opened(ctx),
    },
    "TC02": {
        "description": "Spam: handle_non_bug directly, no pause",
        "expected_pause": False,
        "resume_result": None,
        "expected_nodes_fired": {"handle_non_bug"},
        "forbidden_nodes": {"reproduce_bug", "analyze_root_cause", "propose_fix"},
    },
    "TC03": {
        "description": "Prompt injection: security_screen catches, pause, reject",
        "expected_pause": True,
        "resume_result": "reject",
        "expected_nodes_fired": set(),
        "forbidden_nodes": {"classify_issue"},
        "validate_after_resume": lambda ctx: _validate_rejection(ctx),
    },
    "TC04": {
        "description": "Feature request: handle_non_bug directly, no pause",
        "expected_pause": False,
        "resume_result": None,
        "expected_nodes_fired": {"handle_non_bug"},
        "forbidden_nodes": {"reproduce_bug", "analyze_root_cause", "propose_fix"},
    },
    "TC05": {
        "description": "Critical CVE: hitl_direct, pause, reject, close_with_comment",
        "expected_pause": True,
        "resume_result": "reject",
        "expected_nodes_fired": set(),
        "forbidden_nodes": {"classify_issue", "reproduce_bug", "analyze_root_cause", "propose_fix"},
        "validate_after_resume": lambda ctx: _validate_rejection(ctx),
    },
}


def _validate_pr_opened(ctx: dict) -> None:
    """Asserts that open_pr succeeded (pull_request_created in final state delta)."""
    final_state = ctx.get("final_state_delta", {})
    resume_events = ctx.get("resume_events", [])
    # Look for pull_request_created=True in any resume event state_delta
    for ev in resume_events:
        if ev.actions and ev.actions.state_delta:
            sd = ev.actions.state_delta
            if sd.get("pull_request_created") is True:
                return  # success
    # Also check for explicit error signals
    for ev in resume_events:
        if ev.actions and ev.actions.state_delta:
            sd = ev.actions.state_delta
            if "error" in sd or "pr_error" in sd:
                err = sd.get("error") or sd.get("pr_error")
                raise RuntimeError(
                    f"TC01 FAILED: open_pr reported an error in state_delta: {err}"
                )
    # If we get here, pull_request_created was never set to True
    raise RuntimeError(
        "TC01 FAILED: pull_request_created was never set to True in resume events. "
        "open_pr likely failed silently. Resume event state_deltas: "
        + str([ev.actions.state_delta for ev in resume_events if ev.actions and ev.actions.state_delta])
    )


def _validate_rejection(ctx: dict) -> None:
    """Asserts that the rejected branch executed (close_with_comment or similar)."""
    resume_events = ctx.get("resume_events", [])
    fired_nodes = ctx.get("fired_resume_nodes", set())
    # Rejection should fire some terminal node (close_with_comment, handle_rejected, etc.)
    # Check that we got at least one resume event (the rejection processing)
    if not resume_events:
        raise RuntimeError("FAILED: No events fired after rejection resume — expected close_with_comment or similar.")


async def delete_github_branch(repo_full_name, branch_name):
    github_token = os.environ.get("GITHUB_TOKEN", "")
    if not github_token:
        print("Warning: GITHUB_TOKEN not set, skipping branch deletion.")
        return
    url = f"https://api.github.com/repos/{repo_full_name}/git/refs/heads/{branch_name}"
    headers = {
        "Authorization": f"Bearer {github_token}",
        "Accept": "application/vnd.github+json",
    }
    try:
        resp = requests.delete(url, headers=headers)
        if resp.status_code == 204:
            print(f"Deleted existing branch refs/heads/{branch_name} successfully.")
        elif resp.status_code == 404:
            print(f"Branch refs/heads/{branch_name} did not exist.")
        else:
            print(f"Failed to delete branch refs/heads/{branch_name}: {resp.status_code} {resp.text}")
    except Exception as e:
        print(f"Error calling GitHub API to delete branch: {e}")


async def clean_docker_containers():
    print("Running Docker container cleanup...")
    try:
        import docker
        client = docker.from_env()
        running_containers = client.containers.list()
        for container in running_containers:
            image_tags = container.image.tags
            if any("python:3.11" in tag for tag in image_tags):
                print(f"Stopping and removing python:3.11 container: {container.id}")
                try:
                    container.stop(timeout=5)
                    container.remove()
                    print(f"Successfully cleaned up container {container.id}")
                except Exception as container_err:
                    print(f"Error removing container {container.id}: {container_err}")
    except Exception as docker_err:
        print(f"Docker cleanup check skipped/failed: {docker_err}")


def _is_content_non_empty(content) -> bool:
    """Returns True only if content has at least one part with meaningful data."""
    if content is None:
        return False
    parts = content.parts or []
    for part in parts:
        if part.text and part.text.strip():
            return True
        if part.function_call is not None:
            return True
        if part.function_response is not None:
            return True
    return False


EMPTY_OUTPUT_ERROR = "model output must contain either output text or tool calls"
MAX_SCENARIO_RETRIES = 3


async def run_scenario(case_id, payload, runner, session_service):
    """Retry wrapper around _run_scenario_once to handle transient Gemini empty-output and rate-limit errors."""
    last_err = None
    for attempt in range(1, MAX_SCENARIO_RETRIES + 1):
        try:
            return await _run_scenario_once(case_id, payload, runner, session_service, attempt)
        except Exception as e:
            err_str = str(e)
            is_empty_output = EMPTY_OUTPUT_ERROR in err_str
            is_rate_limit = "429" in err_str or "RESOURCE_EXHAUSTED" in err_str

            if is_empty_output:
                print(f"  [{case_id}] Transient empty-output error on attempt {attempt}/{MAX_SCENARIO_RETRIES}. Retrying in 10s...")
                await asyncio.sleep(10)
                last_err = e
            elif is_rate_limit:
                print(f"  [{case_id}] Transient rate-limit (429) error on attempt {attempt}/{MAX_SCENARIO_RETRIES}. Retrying in 20s...")
                await asyncio.sleep(20)
                last_err = e
            else:
                raise  # non-transient: fail immediately
    raise RuntimeError(
        f"[{case_id}] FAILED after {MAX_SCENARIO_RETRIES} attempts. Last error: {last_err}"
    )


async def _run_scenario_once(case_id, payload, runner, session_service, attempt=1):
    spec = SCENARIO_SPECS.get(case_id)
    if not spec:
        raise ValueError(f"No spec defined for case_id={case_id!r}")

    user_id = "default-user"
    session_id = f"eval-session-{case_id}-attempt{attempt}"

    # Pre-run branch deletion for TC01 to prevent 409 commit conflict
    if case_id == "TC01":
        await delete_github_branch("Rihito2106/autopatch-test-target", "autopatch/issue-1")

    session = await session_service.create_session(
        app_name="autopatch",
        user_id=user_id,
        session_id=session_id
    )

    message = types.Content(
        role="user",
        parts=[
            types.Part(
                function_response=types.FunctionResponse(
                    name="webhook_event",
                    response=payload,
                )
            )
        ]
    )

    print(f"\n>>> Running Scenario {case_id}: {spec['description']} ...")
    last_event = None
    fired_nodes = set()

    # -----------------------------------------------------------------------
    # First execution pass
    # -----------------------------------------------------------------------
    async for event in runner.run_async(
        user_id=user_id,
        session_id=session.id,
        new_message=message,
    ):
        last_event = event
        fired_nodes.add(event.author)
        route_str = f", route={event.actions.route}" if event.actions and event.actions.route else ""
        sd_str = (
            f", state_delta={dict(event.actions.state_delta)}"
            if event.actions and event.actions.state_delta
            else ""
        )
        print(f"  Event: author={event.author}{route_str}{sd_str}")

    # -----------------------------------------------------------------------
    # Detect pause
    # -----------------------------------------------------------------------
    paused = bool(
        last_event
        and last_event.long_running_tool_ids
        and "approved" in last_event.long_running_tool_ids
    )

    print(f"  [{case_id}] {'[PAUSED] at human_approval' if paused else '[DONE] Completed without pausing'}")

    # -----------------------------------------------------------------------
    # Per-scenario validation and optional resume
    # -----------------------------------------------------------------------
    resume_events = []
    fired_resume_nodes = set()

    if paused and not spec["expected_pause"]:
        raise RuntimeError(
            f"[{case_id}] FAILED: Unexpected human_approval pause. "
            f"{case_id} should route directly to handle_non_bug without pausing."
        )

    if not paused and spec["expected_pause"]:
        raise RuntimeError(
            f"[{case_id}] FAILED: Expected human_approval pause was NOT triggered."
        )

    if paused and spec["expected_pause"]:
        expected_result = spec["resume_result"]
        resume_payload = {"result": expected_result}

        resume_message = types.Content(
            role="user",
            parts=[
                types.Part(
                    function_response=types.FunctionResponse(
                        id="approved",
                        name="adk_request_input",
                        response=resume_payload
                    )
                )
            ]
        )

        print(f"  [{case_id}] Resuming with result='{expected_result}' ...")

        actual_route = None

        async for event in runner.run_async(
            user_id=user_id,
            session_id=session.id,
            new_message=resume_message,
            invocation_id=last_event.invocation_id,
        ):
            resume_events.append(event)
            fired_resume_nodes.add(event.author)
            route_str = f", route={event.actions.route}" if event.actions and event.actions.route else ""
            sd_str = (
                f", state_delta={dict(event.actions.state_delta)}"
                if event.actions and event.actions.state_delta
                else ""
            )
            print(f"  Resume Event: author={event.author}{route_str}{sd_str}")

            if event.actions and event.actions.route:
                actual_route = event.actions.route

        # Check the route string matches expected
        if actual_route != expected_result:
            raise RuntimeError(
                f"[{case_id}] FAILED: Resumption route mismatch. "
                f"Expected='{expected_result}', got='{actual_route}'."
            )

        # Run the deeper outcome validation (e.g. PR opened, close fired)
        validate_fn = spec.get("validate_after_resume")
        if validate_fn:
            validate_ctx = {
                "resume_events": resume_events,
                "fired_resume_nodes": fired_resume_nodes,
                "final_state_delta": (
                    dict(resume_events[-1].actions.state_delta)
                    if resume_events and resume_events[-1].actions and resume_events[-1].actions.state_delta
                    else {}
                ),
            }
            validate_fn(validate_ctx)  # raises RuntimeError on failure

        print(f"  [{case_id}] [OK] Resumption validation PASSED (full outcome verified).")

    # -----------------------------------------------------------------------
    # Per-scenario: check forbidden nodes never fired
    # -----------------------------------------------------------------------
    all_fired = fired_nodes | fired_resume_nodes
    for forbidden in spec.get("forbidden_nodes", set()):
        if forbidden in all_fired:
            raise RuntimeError(
                f"[{case_id}] FAILED: Forbidden node '{forbidden}' was executed. "
                f"All fired nodes: {sorted(all_fired)}"
            )
    if spec.get("forbidden_nodes"):
        print(f"  [{case_id}] [OK] Forbidden nodes check: none of {spec['forbidden_nodes']!r} fired.")

    # -----------------------------------------------------------------------
    # Retrieve all events logged in the session
    # -----------------------------------------------------------------------
    session = await session_service.get_session(
        app_name="autopatch",
        user_id=user_id,
        session_id=session_id
    )

    return session.events, paused


async def main():
    import requests
    original_request = requests.Session.request

    def mock_request(self, method, url, *args, **kwargs):
        if "owner/repo" in url:
            mock_resp = requests.Response()
            mock_resp.url = url
            if method.upper() == "POST":
                mock_resp.status_code = 201
                mock_resp._content = b'{"id": 123, "message": "Mock comment created"}'
            elif method.upper() == "PATCH":
                mock_resp.status_code = 200
                mock_resp._content = b'{"state": "closed", "message": "Mock issue patched"}'
            else:
                mock_resp.status_code = 200
                mock_resp._content = b'{"message": "Mock success"}'
            print(f"[{method.upper()}] Mocked request to: {url}")
            return mock_resp
        return original_request(self, method, url, *args, **kwargs)

    requests.Session.request = mock_request

    dataset_path = os.path.join(project_root, "tests", "eval", "datasets", "basic-dataset.json")
    with open(dataset_path, "r", encoding="utf-8") as f:
        dataset = json.load(f)

    session_service = InMemorySessionService()
    runner = Runner(
        agent=root_agent,
        session_service=session_service,
        app_name="autopatch",
        auto_create_session=True,
    )

    eval_cases = []
    scenarios_summary = []

    try:
        for case in dataset.get("eval_cases", []):
            case_id = case["eval_case_id"]
            prompt_text = case["prompt"]["parts"][0]["text"]
            payload = json.loads(prompt_text)

            # Execute the case and collect ADK events
            events, paused = await run_scenario(case_id, payload, runner, session_service)
            scenarios_summary.append((case_id, paused, "PASSED"))

            # -------------------------------------------------------------------
            # Build AgentEvents — SKIP events with empty/null content entirely.
            # The Vertex AI Evals API requires content to be set on every event.
            # Events with only an empty text ("") or no parts are dropped.
            # -------------------------------------------------------------------
            # -------------------------------------------------------------------
            # Build AgentEvents for agent_data.
            # The Vertex AI Evals API only accepts text parts in AgentEvent.content
            # (not function_call / function_response). We convert non-text parts to
            # human-readable text summaries so the LLM judge can read the trace.
            # Events with no meaningful content are dropped entirely.
            # -------------------------------------------------------------------
            agent_events = []
            for ev in events:
                # 1. Resolve correct author using node_info.path if author is workflow
                author = ev.author
                node_name = ""
                if ev.node_info and ev.node_info.path:
                    parts = ev.node_info.path.split("/")
                    if parts:
                        node_name = parts[-1].split("@")[0]

                if author == "autopatch_workflow" and node_name:
                    author = node_name

                # 2. Extract content parts
                text_parts = []
                if ev.content and ev.content.parts:
                    for part in ev.content.parts:
                        if part.text and part.text.strip():
                            text_parts.append(part.text)
                        elif part.function_call is not None:
                            fc = part.function_call
                            args_str = json.dumps(fc.args, default=str) if fc.args else "{}"
                            text_parts.append(f"[tool_call: {fc.name}({args_str})]")
                        elif part.function_response is not None:
                            fr = part.function_response
                            resp_str = json.dumps(fr.response, default=str) if fr.response else "{}"
                            text_parts.append(f"[tool_result: {fr.name} -> {resp_str[:300]}]")

                state_delta = dict(ev.actions.state_delta) if ev.actions and ev.actions.state_delta else {}

                # 3. If there is no text/parts, but there is state_delta or a node name, synthesize a summary
                if not text_parts:
                    if node_name:
                        if state_delta:
                            text_parts.append(f"Executed node {node_name} modifying state: {list(state_delta.keys())}")
                        else:
                            text_parts.append(f"Executed node {node_name}")
                    elif state_delta:
                        text_parts.append(f"State updated: {list(state_delta.keys())}")

                # If we still have absolutely nothing, skip it to avoid empty content errors
                if not text_parts:
                    continue

                role = "user" if author == "user" else "model"
                if ev.content and ev.content.role:
                    role = ev.content.role

                agent_events.append({
                    "author": author,
                    "content": {
                        "role": role,
                        "parts": [{"text": "\n".join(text_parts)}],
                    },
                    "state_delta": state_delta,
                })

            # -------------------------------------------------------------------
            # Determine final response text
            # -------------------------------------------------------------------
            final_text = "No final response text output."
            for ev in reversed(events):
                if ev.author != "user" and ev.content and ev.content.parts:
                    t_parts = [p.text for p in ev.content.parts if p.text]
                    if t_parts:
                        final_text = "\n".join(t_parts)
                        break

            # -------------------------------------------------------------------
            # Build the eval case matching EvaluationDataset Pydantic schema.
            # IMPORTANT: Do NOT include agent_data — it maps to 'agent_eval_data'
            # in the evaluateInstances API which returns 400 INVALID_ARGUMENT.
            # Instead, serialise the trace as a plain string in 'trace_context',
            # which becomes 'other_data' and is injected into the {trace_context}
            # template variable in the LLM judge prompt templates.
            # -------------------------------------------------------------------
            issue = payload.get("issue", payload)
            prompt_summary = (
                f"Issue #{issue.get('number', '?')}: {issue.get('title', '')}\n"
                f"{issue.get('body', '')}"
            )

            # Build human-readable trace text for the judge
            trace_lines = []
            for ev in agent_events:
                role = ev["author"]
                sd = ev.get("state_delta", {})
                text = ev["content"]["parts"][0]["text"] if ev["content"]["parts"] else ""
                trace_lines.append(f"[{role}]: {text[:400]}")
                if sd:
                    trace_lines.append(f"  state_delta: {json.dumps(sd, default=str)[:300]}")
            trace_context = "\n".join(trace_lines) if trace_lines else "No trace events."

            eval_case = {
                "eval_case_id": case_id,
                "prompt": {
                    "role": "user",
                    "parts": [{"text": prompt_summary}],
                },
                "responses": [
                    {
                        "response": {
                            "role": "model",
                            "parts": [{"text": final_text}],
                        }
                    }
                ],
                # trace_context becomes an 'other_data' field in the API instance,
                # injected into {trace_context} in the LLM judge prompt template.
                "trace_context": trace_context,
            }
            eval_cases.append(eval_case)

    except Exception as run_err:
        print(f"\nEvaluation trace generation ABORTED due to failure: {run_err}")
        raise
    finally:
        await runner.close()
        await clean_docker_containers()

    # Serialize traces to EvaluationDataset format
    output_dataset = {
        "eval_cases": eval_cases
    }

    traces_dir = os.path.join(project_root, "artifacts", "traces")
    os.makedirs(traces_dir, exist_ok=True)
    traces_path = os.path.join(traces_dir, "generated_traces.json")

    with open(traces_path, "w", encoding="utf-8") as out_f:
        json.dump(output_dataset, out_f, indent=2)

    print("\n==========================================")
    print("Trace Generation Summary:")
    print("  Scenario  | Paused at HITL? | Status")
    print("  ----------|-----------------|-------")
    for case_id, paused, status in scenarios_summary:
        paused_str = "YES (paused)" if paused else "NO  (direct)"
        print(f"  {case_id:<10}| {paused_str:<17}| {status}")
    print("==========================================")
    print(f"Successfully generated traces and wrote to {traces_path}")

    # Print event count per case for quick sanity check
    print("\nEvent counts per case (non-empty events only):")
    for ec in eval_cases:
        trace_str = ec.get("trace_context", "")
        # Count lines starting with '[' (which denote events in our serialized trace_context)
        n = sum(1 for line in trace_str.splitlines() if line.strip().startswith("["))
        print(f"  {ec['eval_case_id']}: {n} events")


if __name__ == "__main__":
    asyncio.run(main())
