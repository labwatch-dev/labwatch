# Contributing to labwatch

Thanks for your interest in contributing! Here's how to get started.

## Development setup

```bash
git clone https://github.com/labwatch-dev/labwatch.git
cd labwatch/server
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
ADMIN_SECRET=dev uvicorn app:app --reload --port 8097
```

Visit `http://localhost:8097/demo` to see the demo dashboard.

## Agent (Go)

```bash
cd agent
go build -o labwatch ./cmd/labwatch/
```

## What to work on

- Check [open issues](https://github.com/labwatch-dev/labwatch/issues) for bugs and feature requests
- NLQ patterns: add new query types in `server/nlq.py` and response templates in `server/nlq_templates.py`
- Translations: add or improve translations in `server/translations/`
- Agent collectors: add new metric sources in `agent/internal/collector/`

## Pull requests

1. Fork the repo and create a feature branch
2. Make your changes with clear commit messages
3. Test locally (run the server, check the demo page)
4. Open a PR with a description of what changed and why

## Code style

- Python: follow existing patterns, no strict formatter enforced yet
- Go: `gofmt`
- Templates: vanilla HTML/CSS/JS, no build step

## License

By contributing, you agree that your contributions will be licensed under the project's existing licenses (AGPL-3.0 for server, MIT for agent).
