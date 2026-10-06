import os
from typing import Any, Dict, List, Optional

import httpx
from mcp.server.fastmcp import FastMCP

API_BASE = os.getenv("RANSOMLOOK_API", "https://www.ransomlook.io/api")
TIMEOUT = float(os.getenv("RANSOMLOOK_TIMEOUT", "20"))

mcp = FastMCP(
    "RansomLook",
    instructions=(
        "Read-only RansomLook intelligence connector. "
        "Use this server for current ransomware leak-site intelligence. "
        "Do not invent results. When returning results, preserve the source URL "
        "and discovered date when available."
    ),
)

async def get(path: str, params: Optional[Dict[str, Any]] = None) -> Any:
    async with httpx.AsyncClient(timeout=TIMEOUT, follow_redirects=True) as client:
        r = await client.get(f"{API_BASE}{path}", params=params)
        r.raise_for_status()
        return r.json()

@mcp.tool()
async def recent_posts(days: int = 7) -> List[Dict[str, Any]]:
    """Get ransomware leak-site posts discovered within the requested number of days."""
    if days < 1 or days > 30:
        raise ValueError("days must be between 1 and 30")
    return await get("/posts", {"days": days})

@mcp.tool()
async def search_posts(query: str) -> List[Dict[str, Any]]:
    """Search RansomLook posts for an organization, domain, group, keyword, or other exact/partial term."""
    if not query.strip():
        raise ValueError("query must not be empty")
    return await get("/search", {"query": query.strip()})

@mcp.tool()
async def group_details(group: str) -> Any:
    """Get details for a ransomware group, including known leak locations when available."""
    if not group.strip():
        raise ValueError("group must not be empty")
    return await get(f"/group/{group.strip()}")

@mcp.tool()
async def actor_profile(actor: str) -> Dict[str, Any]:
    """Get a RansomLook threat-actor profile, aliases, and related groups when available."""
    if not actor.strip():
        raise ValueError("actor must not be empty")
    return await get(f"/actor/{actor.strip()}")

@mcp.tool()
async def crypto_addresses(group: str) -> Dict[str, Any]:
    """Get cryptocurrency addresses associated with a ransomware group when available."""
    if not group.strip():
        raise ValueError("group must not be empty")
    return await get(f"/crypto/{group.strip()}")

if __name__ == "__main__":
    mcp.run(transport="streamable-http")
