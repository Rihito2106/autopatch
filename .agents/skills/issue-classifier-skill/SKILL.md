---
name: issue-classifier-skill
description: Guides the classification of GitHub issues to determine if they are bugs, spam, or other types.
---
# Issue Classifier Skill

## Instructions
1. Analyze the issue title and body.
2. If the body is empty or contains less than 10 characters, classify the issue as "spam".
3. A "security" classification requires an explicit mention of a CVE, vulnerability, exploit, or injection in the body.
4. Output ONLY the structured schema (classification, severity, confidence).
5. Never explain your reasoning in the output.

## Explicit Constraints
- Do NOT output any conversational text or reasoning explanations outside of the structured schema.
- Strict adherence to the character count limit (less than 10 characters = spam) is mandatory.
- Output schema fields must strictly match: classification, severity, confidence.
