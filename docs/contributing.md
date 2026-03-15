# Contributing to KadeAI

Thanks for your interest in contributing! Here's how to get started.

## Getting Started

1. Fork the repo on GitHub
2. Clone your fork: `git clone https://github.com/YOUR_USERNAME/KadeAI.git`
3. Create a branch: `git checkout -b feature/your-feature-name`
4. Make your changes
5. Run tests: `pytest tests/`
6. Push and open a pull request

## Code Style

- Python 3.10+
- Follow PEP8
- All modules must implement `async execute(self, action, params) -> str`
- Keep modules self-contained — no cross-module imports

## Ideas for Contributions

- New modules (e.g. password auditing, SSL checker, subdomain enumerator)
- Better report templates (HTML, PDF output)
- A web UI (FastAPI + React)
- More test coverage
- Docker support

## Reporting Issues

Open a GitHub issue with:
- What you expected to happen
- What actually happened
- Steps to reproduce
- Your OS and Python version
