## AutoPatch Graph Workflow

```mermaid
flowchart TD
    %% Define Styles & Classes
    classDef preLlmGate fill:#ff9966,stroke:#333,stroke-width:2px;
    classDef hitl fill:#99ccff,stroke:#333,stroke-width:2px;
    classDef llmAgent fill:#b3ffb3,stroke:#333,stroke-width:1px;
    classDef external fill:#f2f2f2,stroke:#333,stroke-width:1px,stroke-dasharray: 5 5;
    classDef normalNode fill:#ffffff,stroke:#333,stroke-width:1px;

    %% Nodes definition
    webhook[GitHub Webhook Event]:::normalNode
    pubsub[Google Cloud Pub/Sub Topic]:::normalNode
    transform[Dashboard / Webhook Transform Layer<br>FastAPI: /webhook]:::normalNode
    runtime[Agent Runtime<br>runner.run_async]:::normalNode

    node1[1. parse_issue<br>Payload Parser Node]:::normalNode
    node2[2. security_screen<br>Sanitization & Check<br><b>pre-LLM gate</b>]:::preLlmGate
    node3[3. classify_issue<br>LlmAgent: flash-lite]:::llmAgent
    node4[4. route_issue<br>Deterministic Router]:::normalNode
    node5[5. reproduce_bug<br>Docker VM/pytest]:::normalNode

    prep_root_cause[prep_root_cause]:::normalNode
    node6[6. analyze_root_cause<br>LlmAgent: flash-lite]:::llmAgent
    node7[7. fetch_files_for_fix<br>Fetch repo files]:::normalNode
    node8[8. propose_fix<br>LlmAgent: flash-lite]:::llmAgent
    node9[9. validate_diff<br>Validator]:::normalNode
    node10[10. security_audit<br>Semgrep node]:::normalNode

    node11[11. human_approval<br>maintainer dashboard<br>HITL Pause Box]:::hitl

    prep_non_bug[prepare_non_bug]:::normalNode
    handle_non_bug[handle_non_bug<br>LlmAgent: flash-lite]:::llmAgent

    open_pr[open_pr<br>Node]:::normalNode
    close_comment[close_with_comment<br>Node]:::normalNode

    output_pr[PR opened]:::normalNode
    output_comment[Comment posted]:::normalNode

    %% External Services
    github_mcp[GitHub MCP Service<br>REST Fallback]:::external
    semgrep_mcp[Semgrep MCP Service]:::external

    %% Flow/Connections
    webhook --> pubsub
    pubsub -- "Push Subscription" --> transform
    transform -- "Background Task" --> runtime
    runtime -- "START" --> node1
    node1 --> node2

    %% Pre-LLM Gate logic
    node2 -- "injection_flagged" --> node11
    node2 -- "__DEFAULT__" --> node3

    node3 --> node4

    node4 -- "bug_pipeline" --> node5
    node4 -- "non_bug" --> prep_non_bug
    node4 -- "hitl_direct" --> node11

    node5 --> prep_root_cause
    prep_root_cause --> node6
    node6 --> node7
    node7 --> node8
    node8 --> node9

    node9 -- "retry: format invalid" --> node8
    node9 -- "success" --> node10
    node9 -- "__DEFAULT__" --> node11

    node10 -- "success" --> node11

    %% Non-bug path
    prep_non_bug --> handle_non_bug

    %% HITL choices
    node11 -- "approve" --> open_pr
    node11 -- "reject" --> close_comment

    open_pr --> output_pr
    close_comment --> output_comment

    %% External service interactions
    node6 -.-> github_mcp
    handle_non_bug -.-> github_mcp
    node7 -.-> github_mcp
    node10 -.-> semgrep_mcp
    open_pr -.-> github_mcp
    close_comment -.-> github_mcp
```

### Text Fallback
```

                                  ┌──────────────────────────────┐
                                  │    GitHub Webhook Event      │
                                  └──────────────┬───────────────┘
                                                 │
                                                 ▼
                                  ┌──────────────────────────────┐
                                  │   Google Cloud Pub/Sub Topic │
                                  └──────────────┬───────────────┘
                                                 │  Push Subscription
                                                 ▼
                                  ┌──────────────────────────────┐
                                  │   Dashboard / Webhook        │
                                  │     Transform Layer          │
                                  │   (FastAPI: /webhook)        │
                                  └──────────────┬───────────────┘
                                                 │  Background Task
                                                 ▼
                                  ┌──────────────────────────────┐
                                  │        Agent Runtime         │
                                  │   (runner.run_async)         │
                                  └──────────────┬───────────────┘
                                                 │  START
                                                 ▼
                                  ┌──────────────────────────────┐
                                  │ 1. parse_issue               │
                                  │    (Payload Parser Node)     │
                                  └──────────────┬───────────────┘
                                                 │
                                                 ▼
  ┌──────────────────────────┐    ┌──────────────────────────────┐
  │      pre-LLM gate        │◀───│ 2. security_screen           │
  │ • Redacts injections     │    │    (Sanitization & Check)    │
  │ • Bypasses LLMs directly │    └──────────────┬───────────────┘
  └──────────────────────────┘                   │
                                                 ├────────────────────────────┐
                                   (__DEFAULT__) │                            │ (injection_flagged)
                                                 ▼                            │
                                  ┌──────────────────────────────┐            │
                                  │ 3. classify_issue            │            │
                                  │    [LlmAgent: flash-lite]    │            │
                                  └──────────────┬───────────────┘            │
                                                 │                            │
                                                 ▼                            │
                                  ┌──────────────────────────────┐            │
                                  │ 4. route_issue               │            │
                                  │    (Deterministic Router)    │            │
                                  └──────────────┬───────────────┘            │
                                                 │                            │
         ┌───────────────────────────────────────┼────────────────────────┐   │
         │ (bug_pipeline)                        │ (non_bug)              │   │ (hitl_direct)
         ▼                                       ▼                        ▼   │
┌──────────────────┐                    ┌──────────────────┐              │   │
│ 5. reproduce_bug │                    │ prepare_non_bug  │              │   │
│ (Docker VM/pytest)                    └────────┬─────────┘              │   │
└────────┬─────────┘                             │                        │   │
         │                                       ▼                        │   │
         ▼                              ┌──────────────────┐              │   │
┌──────────────────┐                    │ handle_non_bug   │              │   │
│ prep_root_cause  │                    │ [LlmAgent:       │              │   │
└────────┬─────────┘                    │  flash-lite]     │              │   │
         │                              └────────┬─────────┘              │   │
         ▼                                       │                        │   │
┌──────────────────┐                             │ (GitHub MCP)           │   │     ┌────────────────┐
│ 6. analyze_      │                             ├────────────────────────┼───┼────▶│   GitHub MCP   │
│    root_cause    │                             │                        │   │     │   Service      │
│ [LlmAgent:       │                             │                        │   │     │ (REST Fallback)│
│  flash-lite]     │                             │                        │   │     └───────▲────────┘
└────────┬─────────┘                             │                        │   │             │
         │                                       │                        │   │             │
         ▼                                       │                        │   │             │
┌──────────────────┐                             │                        │   │             │
│ 7. fetch_files   │─────────────────────────────┼────────────────────────┼───┘             │
│    _for_fix      │ (Fetch repo files)          │                        │                 │
└────────┬─────────┘                             │                        │                 │
         │                                       │                        │                 │
         ▼                                       │                        │                 │
┌──────────────────┐                             │                        │                 │
│ 8. propose_fix   │◀──────────────────────┐     │                        │                 │
│ [LlmAgent:       │                       │     │                        │                 │
│  flash-lite]     │                       │     │                        │                 │
└────────┬─────────┘                       │     │                        │                 │
         │                                 │     │                        │                 │
         ▼                                 │     │                        │                 │
┌──────────────────┐                       │     │                        │                 │
│ 9. validate_diff │───────────────────────┘     │                        │                 │
│    (Validator)   │ (retry: format invalid)     │                        │                 │
└────────┬─────────┘                             │                        │                 │
         │                                       │                        │                 │
         ├───────────────────────┐               │                        │                 │
         │ (success)             │ (__DEFAULT__) │                        │                 │
         ▼                       ▼               ▼                        │                 │
┌──────────────────┐    ┌──────────────────────────────────┐              │                 │
│10. security_audit│───▶│          human_approval          │◀─────────────┴                 │
│  (Semgrep node)  │    │                                  │                                │
└────────┬─────────┘    │  ┌────────────────────────────┐  │                                │
         │              │  │    maintainer dashboard    │  │                                │
         │              │  │     (HITL Pause Box)       │  │                                │
         │              │  └────────────────────────────┘  │                                │
         │              └────────────────┬─────────────────┘                                │
         │                               │                                                  │
         │                   ┌───────────┴───────────┐                                      │
         │                   │ (approve)             │ (reject)                             │
         ▼                   ▼                       ▼                                      │
 ┌──────────────┐       ┌──────────┐            ┌──────────┐                                │
 │ Semgrep MCP  │       │ 11.      │            │ close_   │                                │
 │ Service      │       │ open_pr  │            │ with_    │                                │
 └──────────────┘       │  (Node)  │            │ comment  │                                │
                        └────┬─────┘            └────┬─────┘                                │
                             │                       │                                      │
                             └───────────┬───────────┘ (GitHub MCP)                         │
                                         │                                                  │
                                         ▼                                                  │
                                   ┌───────────┐                                            │
                                   │ PR opened │                                            │
                                   │     /     │────────────────────────────────────────────┘
                                   │  Comment  │
                                   │  posted   │
                                   └───────────┘
```

## Highlights & Specifications

1. **Transform & Webhook Path **:
   - **GitHub Webhook** triggers a message delivery.
   - Because a push subscription cannot target a direct `:query` API endpoint, the request lands on **Google Cloud Pub/Sub**, which pushes to the **FastAPI Webhook Transform Layer** (`/webhook`).
   - The payload is normalized, decoded if base64-encoded, and offloaded to an asynchronous background task within the **Agent Runtime** using `runner.run_async()`.

2. **Core 11-Node Chain**:
   - **Node 1**: `parse_issue` — Extracts payload.
   - **Node 2**: `security_screen` — High-priority Pre-LLM Gate. Checks for prompt injections and API secrets, bypassing subsequent LLMs immediately by routing to human approval if flagged.
   - **Node 3**: `classify_issue` — Triages category (e.g. bug, non-bug, spam) and severity.
   - **Node 4**: `route_issue` — Route resolution logic.
   - **Node 5**: `reproduce_bug` — Automated test reproduction inside Docker.
   - **Node 6**: `analyze_root_cause` — Diagnoses traceback and suggests allowed target files.
   - **Node 7**: `fetch_files_for_fix` — Obtains code files from repo.
   - **Node 8**: `propose_fix` — Generates patch diff.
   - **Node 9**: `validate_diff` — Asserts diff conformity and handles loop retry.
   - **Node 10**: `security_audit` — Post-patch check using Semgrep.
   - **Node 11**: `human_approval` / `open_pr` — Final HITL gate to merge.

3. **Model Selection**:
   - Every `LlmAgent` node (`classify_issue`, `analyze_root_cause`, `propose_fix`, `handle_non_bug`) is configured to use `gemini-2.5-flash-lite` by default (denoted as **flash-lite**).

4. **External Integrations**:
   - **GitHub MCP Service** handles issue commenting, PR creation, labelling, and close actions.
   - **Semgrep MCP Service** runs static analysis over the generated diff.
