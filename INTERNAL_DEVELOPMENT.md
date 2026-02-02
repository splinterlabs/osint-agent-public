# Internal Development Guide

This repository uses a **private upstream + public fork** model.

## Repository Structure

```
Private: osint-agent-private (this repo)
    ↓ sync script
Public: osint-agent (GitHub public)
```

## Directory Layout

```
osint-agent-private/
├── .private/              # NEVER synced to public
│   ├── integrations/      # Proprietary API clients
│   ├── intel/             # Internal threat intelligence
│   ├── enterprise/        # Enterprise-only features
│   └── docs/              # Internal documentation
├── src/osint_agent/       # Core package (synced)
├── mcp-server/            # MCP tools (synced)
├── scripts/
│   └── sync-to-public.sh  # Sync script (not synced)
└── ...
```

## What Stays Private

The following are **never** synced to public:

| Pattern | Purpose |
|---------|---------|
| `.private/` | All private code and data |
| `*.private.*` | Any file with `.private.` in name |
| `INTERNAL_*.md` | Internal documentation |
| `.sync-config` | Sync configuration |
| `scripts/sync-to-public.sh` | The sync script itself |
| `data/campaigns/*.json` | Campaign data |
| `data/context/*.json` | Investigation context |

## Workflow

### Daily Development

1. Work in this private repo normally
2. All features start here
3. Use `.private/` for proprietary code

### Adding Private Features

```bash
# Private integration example
mkdir -p .private/integrations
cat > .private/integrations/internal_api.py << 'EOF'
"""Internal-only API client."""
class InternalThreatFeed:
    ...
EOF
```

### Syncing to Public

When ready to release publicly:

```bash
# 1. Set up sync config (first time only)
cp .sync-config.example .sync-config
# Edit .sync-config with public repo URL

# 2. Preview what will be synced
./scripts/sync-to-public.sh --dry-run

# 3. Sync to public
./scripts/sync-to-public.sh
```

### Creating Public Releases

1. Sync latest changes to public
2. In public repo, create release tag:
   ```bash
   cd /path/to/public/repo
   git tag -a v0.2.0 -m "Release notes..."
   git push origin v0.2.0
   ```

## Best Practices

### Naming Conventions

- `*.private.py` - Private Python modules
- `*.private.json` - Private config files
- `INTERNAL_*.md` - Internal docs
- `.private/` - Private directory

### Conditional Imports

For optional private features:

```python
# In public code
try:
    from osint_agent.private.enterprise import EnterpriseFeature
    HAS_ENTERPRISE = True
except ImportError:
    HAS_ENTERPRISE = False

def some_function():
    if HAS_ENTERPRISE:
        return EnterpriseFeature().run()
    return basic_implementation()
```

### Testing

- Public tests in `tests/`
- Private tests in `.private/tests/`
- CI runs both in private repo, only public tests in public repo

## Migration Checklist

When moving code from private to public:

- [ ] Remove any hardcoded internal URLs/IPs
- [ ] Remove internal API keys or credentials
- [ ] Remove references to internal systems
- [ ] Update documentation for public use
- [ ] Add to sync exclude list if needed
- [ ] Test in isolation before syncing
