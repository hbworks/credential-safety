"""Credential Safety Plugin - Multi-layer secret redaction."""
import logging

try:
    from . import patterns, hooks
except (ImportError, ValueError):
    import patterns, hooks

logger = logging.getLogger(__name__)



def register(ctx):
    """Register credential safety plugin."""
    
    # Layer 1: Pattern-based redaction
    count = ctx.register_redaction_patterns(patterns.PATTERNS)
    logger.info(f"Registered {count} custom redaction patterns")
    
    # Layer 2: Tool result transformation
    ctx.register_hook("transform_tool_result", hooks.redact_tool_result)
    logger.debug("Registered transform_tool_result hook")
    
    # Layer 3: LLM output transformation
    ctx.register_hook("transform_llm_output", hooks.redact_llm_output)
    logger.debug("Registered transform_llm_output hook")
    
    # Layer 4: Terminal output transformation
    ctx.register_hook("transform_terminal_output", hooks.redact_terminal_output)
    logger.debug("Registered transform_terminal_output hook")
    
    logger.info("Credential safety plugin initialized")


__all__ = ["register"]