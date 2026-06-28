---
name: diagram-vs-code-skill
description: Guides the diagram_check LlmAgent in comparing architecture diagrams with proposed code diffs.
---
# Diagram vs Code Skill

## Instructions
1. Compare the architecture diagram image against the proposed diff.
2. List only concrete inconsistencies (e.g., "diff adds a new dependency on module X which is not shown in the diagram").
3. If no inconsistencies: output consistent=true, inconsistencies=[].
4. Do NOT comment on style, naming, or non-architectural concerns.

## Explicit Constraints
- Do NOT flag stylistic, naming, or cosmetic differences.
- If no architectural discrepancies are found, consistent MUST be set to true and inconsistencies list MUST be empty [].
