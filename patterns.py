"""Custom credential patterns for redaction."""

PATTERNS = [
    # Non-standard credentials
    r"mycompany_token_[A-Za-z0-9]{32,}",
    r"internal_secret_[A-Za-z0-9_-]{20,}",
    r"custom_api_key_[0-9a-f]{40,}",
    
    # Common but often missed formats
    r"Bearer\s+[A-Za-z0-9\-._~+/]+=*",
    r"authorization:\s*[A-Za-z0-9\-._~+/]+=*",
]
