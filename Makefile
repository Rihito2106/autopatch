.PHONY: install playground eval deploy serve

install:
	uv tool install google-agents-cli
	agents-cli install

playground:
	agents-cli playground

eval:
	agents-cli eval generate && agents-cli eval grade

deploy:
	agents-cli deploy

serve:
	uv run uvicorn autopatch.fast_api_app:app --host 0.0.0.0 --port 8080
