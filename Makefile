.PHONY: install playground eval deploy

install:
	uv tool install google-agents-cli
	agents-cli install

playground:
	agents-cli playground

eval:
	agents-cli eval generate && agents-cli eval grade

deploy:
	agents-cli deploy
