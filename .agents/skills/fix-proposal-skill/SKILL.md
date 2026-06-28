---
name: fix-proposal-skill
description: Guides the propose_fix LlmAgent in proposing code modifications that fix bugs.
---
# Fix Proposal Skill

## Instructions
1. Write the MINIMAL diff. Touch only files listed in files_to_modify.
2. Do NOT refactor unrelated code. Do NOT add features.
3. Always add or update at least one test that would have caught this bug.
4. Output in standard unified diff format (--- a/file +++ b/file).
5. Explain the fix in one paragraph under the diff.

## Explicit Constraints
- Unrelated code refactoring or adding features is strictly prohibited.
- Diff must follow the standard unified diff format precisely.
- At least one test addition or update is mandatory in the diff.
