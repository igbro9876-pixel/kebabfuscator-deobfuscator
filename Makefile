.PHONY: test test-verbose lint clean help

help:
	@echo "Usage:"
	@echo "  make test         Run the full test suite"
	@echo "  make test-verbose Run tests with verbose output"
	@echo "  make clean        Remove generated output files"

test:
	python -m unittest discover -s tests

test-verbose:
	python -m unittest discover -s tests -v

clean:
	find . -name "*.deobfuscated.lua" -delete
	find . -name "*.lifted.lua" -delete
	find . -name "*.antitamper.lua" -delete
	find . -name "__pycache__" -type d -exec rm -rf {} + 2>/dev/null || true
	find . -name "*.pyc" -delete
