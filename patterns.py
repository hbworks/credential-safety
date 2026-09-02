"""Custom credential patterns for redaction."""

PATTERNS = [
    # Non-standard / Custom credentials
    r"mycompany_token_[A-Za-z0-9]{32,}",
    r"internal_secret_[A-Za-z0-9_-]{20,}",
    r"custom_api_key_[0-9a-f]{40,}",

    # Standard Auth Headers (explicit literal prefixes to satisfy core pre-screen)
    r"Bearer\s+(?!None\b|null\b|undefined\b|your-)[A-Za-z0-9\-._~+/]{10,}=*",
    r"bearer\s+(?!None\b|null\b|undefined\b|your-)[A-Za-z0-9\-._~+/]{10,}=*",

    # AI & Cloud Provider Keys (wrapped in group to avoid top-level alternation)
    r"sk-(?:(?:proj-|ant-|api03-|live-|test-)[A-Za-z0-9_\-]{20,}|[A-Za-z0-9]{32,})", # OpenAI / Anthropic
    r"AIza[0-9A-Za-z\-_]{30,40}",                                # Google API Key (Maps, YouTube, Firebase, Gemini)
    r"ya29\.[0-9A-Za-z\-_]{20,}",                                # Google OAuth2 Access Token
    r"hf_[A-Za-z0-9]{30,}",                                      # HuggingFace API Token
    r"AKIA[0-9A-Z]{16}",                                         # AWS Access Key ID

    # Code Hosting & CI/CD
    r"gh[pousr]_[A-Za-z0-9_]{36,}",                             # GitHub Classic Tokens (ghp, gho, ghu, ghs, ghr)
    r"github_pat_[A-Za-z0-9_]{60,}",                            # GitHub Fine-grained PAT
    r"glpat-[A-Za-z0-9\-=_]{20,}",                               # GitLab Personal Access Token

    # SaaS & Communication APIs (split to provide at least 2 literal leading characters)
    r"sk_(?:live|test)_[0-9a-zA-Z]{24,}",                        # Stripe Secret Keys
    r"rk_(?:live|test)_[0-9a-zA-Z]{24,}",                        # Stripe Restricted Keys
    r"SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}",               # SendGrid API Key
    r"SK[0-9a-fA-F]{32}",                                        # Twilio API Key
    r"AC[0-9a-fA-F]{32}",                                        # Twilio Account SID
    r"xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9-]*",       # Slack User/Bot Tokens
    r"xapp-\d-[A-Za-z0-9]{8,}-\d+-[A-Za-z0-9]{8,}",              # Slack App-level Token

    # Standard Cryptographic & Auth Structures
    r"eyJ[A-Za-z0-9-_=]{10,}\.[A-Za-z0-9-_=]{10,}\.?[A-Za-z0-9-_.+/=]*", # JWT Token
    r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----", # Private Keys
]


