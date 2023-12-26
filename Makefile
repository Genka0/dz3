linter:
	@echo "Run linters"
	black .
	isort .
	flake8 .

info:
	echo "Hello"
	@echo "Hello 2"
