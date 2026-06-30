.PHONY: install playground eval deploy serve

install:
	uv tool install google-agents-cli
	agents-cli install

playground:
	agents-cli playground

eval:
	agents-cli eval generate && agents-cli eval grade

generate-traces:
	@echo "NOTE: Docker Desktop must be running before executing generate-traces (for TC01 reproduce_bug sandbox)!"
	uv run python tests/eval/generate_traces.py

grade:
	agents-cli eval grade --config tests/eval/eval_config.yaml --traces artifacts/traces/generated_traces.json

deploy:
	agents-cli deploy

serve:
	uv run uvicorn autopatch.fast_api_app:app --host 0.0.0.0 --port 8080
