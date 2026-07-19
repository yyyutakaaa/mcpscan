"""A well-behaved FastMCP server. Clean test fixture — must yield zero findings."""

from pathlib import Path

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("clean-demo")

WORKSPACE = Path("/srv/workspace")


@mcp.tool()
def greet(name: str) -> str:
    """Return a friendly greeting for the given name."""
    return f"Hello, {name}!"


@mcp.tool()
def read_note(relative_path: str) -> str:
    """Read a note from the workspace notes directory."""
    candidate = (WORKSPACE / "notes" / relative_path).resolve()
    if not candidate.is_relative_to(WORKSPACE / "notes"):
        raise ValueError("path escapes the notes directory")
    return candidate.read_text(encoding="utf-8")
