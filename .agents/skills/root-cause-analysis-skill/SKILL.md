---
name: root-cause-analysis-skill
description: Guides the analyze_root_cause LlmAgent in locating and verifying the root cause of test failures and tracebacks.
---
# Root Cause Analysis Skill

## Instructions
1. Read the traceback line by line before reading any source file.
2. Identify the exact line where the exception originates before looking at callers.
3. Verify files_to_modify list: it must list ONLY files that contain the root cause — not callers, not tests, not config files.
4. If confidence < 0.5, output files_to_modify as an empty list and explain why in the explanation.

## Explicit Constraints
- Do NOT read any source files before analyzing the traceback line by line.
- Do NOT list tests, callers, or config files in files_to_modify.
- If confidence is below 0.5, files_to_modify MUST be an empty list [].
