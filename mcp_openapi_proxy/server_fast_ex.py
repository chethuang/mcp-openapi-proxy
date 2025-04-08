"""
Provides the FastMCP server logic for mcp-openapi-proxy.

This server exposes a pre-defined set of functions based on an OpenAPI specification.
Configuration is controlled via environment variables:
- OPENAPI_SPEC_URL_<hash>: Unique URL per test, falls back to OPENAPI_SPEC_URL.
- TOOL_WHITELIST: Comma-separated list of allowed endpoint paths.
- SERVER_URL_OVERRIDE: Optional override for the base URL from the OpenAPI spec.
- API_KEY: Generic token for Bearer header.
- STRIP_PARAM: Param name (e.g., "auth") to remove from parameters.
- EXTRA_HEADERS: Additional headers in 'Header: Value' format, one per line.
"""

import os
import sys
import json
import requests
from typing import Dict, Any
from mcp import types
from collections.abc import Awaitable, Callable

from mcp.server.fastmcp import FastMCP
import mcp_openapi_proxy.utils_lowlevel as utils_lowlevel
from mcp_openapi_proxy.utils import setup_logging, fetch_openapi_spec

logger = setup_logging(debug=os.getenv("DEBUG", "").lower() in ("true", "1", "yes"))

logger.debug(f"Server CWD: {os.getcwd()}")
logger.debug(f"Server sys.path: {sys.path}")


class FastMCPEX(FastMCP):
    """FastMCP class for OpenAPI proxy with custom logic."""

    def __init__(self, name: str, **settings: Any):
               
        super().__init__(name, **settings)

    def set_tool_list_request_handler(self, handler: Callable):
        
        self._mcp_server.request_handlers[types.ListToolsRequest] = handler
        
        
    def set_tool_request_handler(self, handler: Callable):
        self._mcp_server.request_handlers[types.CallToolRequest] = handler
        


mcp = FastMCPEX("OpenApiProxy-Fast")


def run_simple_server():
    """Runs the FastMCPEX server."""
    logger.debug("Starting run_simple_server_ex")
    spec_url = os.environ.get("OPENAPI_SPEC_URL")
    if not spec_url:
        logger.error("OPENAPI_SPEC_URL environment variable is required for FastMCP mode.")
        sys.exit(1)

    logger.debug("Preloading functions from OpenAPI spec...")
    
    utils_lowlevel.openapi_spec_data = fetch_openapi_spec(spec_url)
    if utils_lowlevel.openapi_spec_data is None:
        logger.error("Failed to fetch OpenAPI spec, no functions to preload.")
        sys.exit(1)
    utils_lowlevel.register_functions(utils_lowlevel.openapi_spec_data)
    
    mcp.set_tool_list_request_handler(utils_lowlevel.list_tools)
    mcp.set_tool_request_handler(utils_lowlevel.dispatcher_handler)

    try:
        logger.debug("Starting MCP server (FastMCPEX version)...")
        mcp.run(transport="sse")
    except Exception as e:
        logger.error(f"Unhandled exception in MCP server (FastMCPEX): {e}", exc_info=True)
        sys.exit(1)

if __name__ == "__main__":
    run_simple_server()
