#!/usr/bin/env python3
import sys
import os
import json

def main():
    # Allowlist of approved commands
    allowlist = [
        "git",
        "pip",
        "pytest",
        "pre-commit",
        "uv",
        "semgrep",
        "agents-cli",
        "python",
        "echo"
    ]

    cmd_to_check = ""
    if len(sys.argv) > 1:
        cmd_to_check = " ".join(sys.argv[1:])

    if not cmd_to_check and not sys.stdin.isatty():
        try:
            stdin_content = sys.stdin.read().strip()
            try:
                data = json.loads(stdin_content)
                if isinstance(data, dict):
                    cmd_to_check = data.get("CommandLine", data.get("command", ""))
            except Exception:
                cmd_to_check = stdin_content
        except Exception:
            pass

    if not cmd_to_check:
        cmd_to_check = os.environ.get("COMMAND_LINE", os.environ.get("CommandLine", ""))

    cmd_to_check = cmd_to_check.strip()
    if not cmd_to_check:
        sys.exit(0)

    first_word = cmd_to_check.split()[0].lower()
    first_word = os.path.basename(first_word).replace(".exe", "")

    if first_word not in allowlist:
        print(f"Error: Command '{first_word}' (from '{cmd_to_check}') is not in the security allowlist!", file=sys.stderr)
        sys.exit(1)

    print(f"Command '{cmd_to_check}' approved.")
    sys.exit(0)

if __name__ == "__main__":
    main()
