# Contributing to Network Watcher

Thank you for your interest in contributing to Network Watcher! This document provides guidelines and information for contributors.

## Code of Conduct

Please be respectful and constructive in all interactions. We welcome contributors of all experience levels.

## Getting Started

### Prerequisites

- Go 1.23 or later
- Linux kernel 5.4+ with BTF support (for eBPF development)
- Clang/LLVM for eBPF compilation
- Git

### Development Setup

1. Fork the repository
2. Clone your fork:
   ```bash
   git clone https://github.com/YOUR_USERNAME/network-watcher.git
   cd network-watcher
   ```

3. Install dependencies:
   ```bash
   make deps
   ```

4. Verify tools are installed:
   ```bash
   make check-tools
   ```

5. Build the project:
   ```bash
   make build
   ```

6. Run tests:
   ```bash
   make test
   ```

## Making Changes

### Branch Naming

Use descriptive branch names:
- `feature/add-new-detection` - New features
- `fix/websocket-reconnect` - Bug fixes
- `docs/update-readme` - Documentation updates
- `refactor/cleanup-store` - Code refactoring

### Coding Standards

- Follow Go conventions and idioms
- Use `gofmt` for formatting (`make fmt`)
- Run the linter before committing (`make lint`)
- Write meaningful commit messages
- Add comments for complex logic
- Keep functions focused and small

### Testing

- Add unit tests for new functionality
- Ensure all existing tests pass
- Test eBPF changes on a real Linux system
- Run the full test suite: `make test`

### Commit Messages

Write clear, concise commit messages:

```
Add DNS resolution caching

- Implement in-memory cache for DNS lookups
- Add cache expiration after 5 minutes
- Reduce redundant DNS queries by 80%
```

## Pull Request Process

1. Create a feature branch from `main`
2. Make your changes with clear commits
3. Run tests and linter locally
4. Push your branch to your fork
5. Open a Pull Request against `main`
6. Fill out the PR template completely
7. Wait for review and address feedback

### PR Guidelines

- Keep PRs focused on a single change
- Include tests for new functionality
- Update documentation if needed
- Ensure CI passes before requesting review
- Be responsive to review feedback

## Project Structure

```
network-watcher/
├── bpf/           # eBPF C programs
├── cmd/           # Main applications
│   ├── sentinel/  # CLI tool
│   └── webui/     # Web dashboard
├── pkg/           # Go packages
│   ├── collector/ # eBPF event collection
│   ├── mcp/       # MCP server
│   ├── store/     # Event storage
│   └── types/     # Shared types
└── scripts/       # Build scripts
```

## Areas for Contribution

### Good First Issues

Look for issues labeled `good first issue` - these are suitable for newcomers.

### Feature Ideas

- Additional threat detection patterns
- New visualization types
- Performance optimizations
- Documentation improvements
- Additional MCP tools

### eBPF Development

If you're working on eBPF code:
- Test on multiple kernel versions
- Ensure ARM64 and x86_64 compatibility
- Document any kernel requirements

## Getting Help

- Open an issue for questions
- Check existing issues for similar problems
- Read the README for usage information

## License

By contributing, you agree that your contributions will be licensed under the MIT License.

---

Thank you for contributing!
