"""Custom credential patterns for redaction."""

PATTERNS = [
    # Non-standard / Custom credentials
    r"mycompany_token_[A-Za-z0-9]{32,}",
    r"internal_secret_[A-Za-z0-9_-]{20,}",
    r"custom_api_key_[0-9a-f]{40,}",

    # Standard Auth Headers
    r"Bearer\s+[A-Za-z0-9\-._~+/]+=*",
    r"authorization:\s*[A-Za-z0-9\-._~+/]+=*",

    # Well-known API Keys & Tokens
    r"sk-(?:proj-|ant-|live-|test-)?[A-Za-z0-9_\-]{20,}",        # OpenAI / Anthropic / Stripe
    r"AKIA[0-9A-Z]{16}",                                         # AWS Access Key ID
    r"gh[pousr]_[A-Za-z0-9_]{36,}",                             # GitHub Tokens (ghp, gho, ghu, ghs, ghr)
    r"glpat-[A-Za-z0-9\-=_]{20,}",                               # GitLab Personal Access Token
    r"xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*",       # Slack Tokens
    r"eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*", # JWT Token
    r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----", # Private Keys
]

