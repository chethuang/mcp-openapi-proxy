"""
utils for Low-Level Server 
"""

import os
import sys
import asyncio
import json
import requests
from jsonpath_ng import parse
from typing import List, Dict, Any
import anyio
from mcp import types
from urllib.parse import unquote
from mcp.server.models import InitializationOptions
from mcp_openapi_proxy.utils import (
    setup_logging,
    normalize_tool_name,
    is_tool_whitelisted,
    is_tool_whitelist_exact,
    parse_api_resp_json_path,
    fetch_openapi_spec,
    build_base_url,
    handle_auth,
    strip_parameters,
    detect_response_type,
    get_additional_headers
)

DEBUG = os.getenv("DEBUG", "").lower() in ("true", "1", "yes")
logger = setup_logging(debug=DEBUG)

tools: List[types.Tool] = []
resources: List[types.Resource] = [
    types.Resource(
        name="spec_file",
        uri="file:///openapi_spec.json",
        description="The raw OpenAPI specification JSON"
    )
]
prompts: List[types.Prompt] = [
    types.Prompt(
        name="summarize_spec",
        description="Summarizes the purpose of the OpenAPI specification",
        arguments=[],
        messages=lambda args: [
            {"role": "assistant", "content": {"type": "text", "text": "This OpenAPI spec defines an API’s endpoints, parameters, and responses, making it a blueprint for devs to build and integrate stuff without errors."}}
        ]
    )
]
openapi_spec_data = None

function_name_resp_json_path_mapping = {}

def get_config_resp_json_path_text(function_name: str, resp_json: dict) -> str:
    if not resp_json:
        return None
    if function_name not in function_name_resp_json_path_mapping:
        return None
    json_path_expr = function_name_resp_json_path_mapping.get(function_name)
    logger.debug(f"fetch json path {function_name}: {json_path_expr}")
    jsonpath_expr = parse(json_path_expr)
    matches = jsonpath_expr.find(resp_json)
    match_json = [match.value for match in matches]
    if not match_json:
        return None
    return json.dumps(match_json)

async def dispatcher_handler(request: types.CallToolRequest) -> types.CallToolResult:
    """Dispatcher handler that routes CallToolRequest to the appropriate function (tool)."""
    global openapi_spec_data
    try:
        function_name = request.params.name
        logger.debug(f"Dispatcher received CallToolRequest for function: {function_name}")
        logger.debug(f"API_KEY: {os.getenv('API_KEY', '<not set>')[:5] + '...' if os.getenv('API_KEY') else '<not set>'}")
        logger.debug(f"STRIP_PARAM: {os.getenv('STRIP_PARAM', '<not set>')}")
        tool = next((tool for tool in tools if tool.name == function_name), None)
        if not tool:
            logger.error(f"Unknown function requested: {function_name}")
            return types.CallToolResult(content=[types.TextContent(type="text", text="Unknown function requested")], isError=False)
        arguments = request.params.arguments or {}
        logger.debug(f"Raw arguments before processing: {arguments}")

        operation_details = lookup_operation_details(function_name, openapi_spec_data)
        if not operation_details:
            logger.error(f"Could not find OpenAPI operation for function: {function_name}")
            return types.CallToolResult(content=[types.TextContent(type="text", text=f"Could not find OpenAPI operation for function: {function_name}")], isError=False)

        operation = operation_details['operation']
        operation['method'] = operation_details['method']
        headers = handle_auth(operation)
        additional_headers = get_additional_headers()
        headers = {**headers, **additional_headers}
        parameters = dict(strip_parameters(arguments))
        method = operation_details['method']
        if method != "GET":
            headers["Content-Type"] = "application/json"

        path = operation_details['path']
        try:
            path = path.format(**parameters)
            logger.debug(f"Substituted path using format(): {path}")
            if method == "GET":
                placeholder_keys = [seg.strip('{}') for seg in operation_details['original_path'].split('/') if seg.startswith('{') and seg.endswith('}')]
                for key in placeholder_keys:
                    parameters.pop(key, None)
        except KeyError as e:
            logger.error(f"Missing parameter for substitution: {e}")
            return types.CallToolResult(content=[types.TextContent(type="text", text=f"Missing parameter: {e}")], isError=False)

        base_url = build_base_url(openapi_spec_data)
        if not base_url:
            logger.critical("Failed to construct base URL from spec or SERVER_URL_OVERRIDE.")
            return types.CallToolResult(content=[types.TextContent(type="text", text="No base URL defined in spec or SERVER_URL_OVERRIDE")], isError=False)

        api_url = f"{base_url.rstrip('/')}/{path.lstrip('/')}"
        request_params = {}
        request_body = None
        if isinstance(parameters, dict):
            merged_params = []
            path_item = openapi_spec_data.get("paths", {}).get(operation_details['original_path'], {})
            if isinstance(path_item, dict) and "parameters" in path_item:
                merged_params.extend(path_item["parameters"])
            if "parameters" in operation:
                merged_params.extend(operation["parameters"])
            path_params_in_openapi = [param["name"] for param in merged_params if param.get("in") == "path"]
            if path_params_in_openapi:
                missing_required = [
                    param["name"] for param in merged_params
                    if param.get("in") == "path" and param.get("required", False) and param["name"] not in arguments
                ]
                if missing_required:
                    logger.error(f"Missing required path parameters: {missing_required}")
                    return types.CallToolResult(content=[types.TextContent(type="text", text=f"Missing required path parameters: {missing_required}")], isError=False)
            if method == "GET":
                request_params = parameters
            else:
                request_body = parameters
        else:
            logger.debug("No valid parameters provided, proceeding without params/body")

        logger.info(f"API Request - URL: {api_url}, Method: {method}")
        logger.info(f"Headers: {headers}")
        logger.info(f"Query Params: {request_params}")
        logger.info(f"Request Body: {request_body}")

        try:
            response = requests.request(
                method=method,
                url=api_url,
                headers=headers,
                params=request_params if method == "GET" else None,
                json=request_body if method != "GET" else None
            )
            response.raise_for_status()
            response_text = (response.text or "No response body").strip()

            fetch_path_text = get_config_resp_json_path_text(function_name=function_name, resp_json=response.json())
            if fetch_path_text:
                response_text = fetch_path_text

            content =  types.TextContent(type="text", text=response_text, id=None)
            final_content = [content]
        except requests.exceptions.RequestException as e:
            logger.error(f"API request failed: {e}")
            return types.CallToolResult(content=[types.TextContent(type="text", text=str(e))], isError=False)
        logger.info(f"Response sent to client: {content}")
        return types.CallToolResult(content=final_content, isError=False)
    except Exception as e:
        logger.error(f"Unhandled exception in dispatcher_handler: {e}", exc_info=True)
        return types.CallToolResult(content=[types.TextContent(type="text", text=f"Internal error: {str(e)}")], isError=False)

async def list_tools(request: types.ListToolsRequest) -> types.ListToolsResult:
    logger.debug("Handling list_tools request - start")
    logger.debug(f"Tools list length: {len(tools)}")
    return types.ListToolsResult(tools=tools)

async def list_resources(request: types.ListResourcesRequest) -> types.ListResourcesResult:
    logger.debug("Handling list_resources request")
    logger.debug(f"Resources list length: {len(resources)}")
    return types.ListResourcesResult(resources=resources, resourceTemplates=[])

async def read_resource(request: types.ReadResourceRequest) -> types.ReadResourceResult:
    logger.debug(f"START read_resource for URI: {request.params.uri}")
    try:
        openapi_url = os.getenv('OPENAPI_SPEC_URL')
        logger.debug(f"Got OPENAPI_SPEC_URL: {openapi_url}")
        if not openapi_url:
            logger.error("OPENAPI_SPEC_URL not set")
            return types.ReadResourceResult(contents=[types.TextResourceContents(type="text", uri=request.params.uri, text="Spec unavailable: OPENAPI_SPEC_URL not set")])
        logger.debug("Fetching spec...")
        spec_data = fetch_openapi_spec(openapi_url)
        logger.debug(f"Spec fetched: {spec_data is not None}")
        if not spec_data:
            logger.error("Failed to fetch OpenAPI spec")
            return types.ReadResourceResult(contents=[types.TextResourceContents(type="text", uri=request.params.uri, text="Spec data unavailable after fetch attempt")])
        logger.debug("Dumping spec to JSON...")
        spec_json = json.dumps(spec_data, indent=2)
        logger.debug(f"Forcing spec JSON return: {spec_json[:50]}...")
        result = types.ReadResourceResult(contents=[types.TextResourceContents(type="text", uri="file:///openapi_spec.json", text=spec_json)])
        logger.debug("Returning result from read_resource")
        return result
    except Exception as e:
        logger.error(f"Error forcing resource: {e}", exc_info=True)
        return types.ReadResourceResult(contents=[types.TextResourceContents(type="text", uri=request.params.uri, text=f"Resource error: {str(e)}")])

async def list_prompts(request: types.ListPromptsRequest) -> types.ListPromptsResult:
    logger.debug("Handling list_prompts request")
    logger.debug(f"Prompts list length: {len(prompts)}")
    return types.ListPromptsResult(prompts=prompts)

async def get_prompt(request: types.GetPromptRequest) -> types.GetPromptResult:
    logger.debug(f"Handling get_prompt request for {request.params.name}")
    prompt = next((p for p in prompts if p.name == request.params.name), None)
    if not prompt:
        logger.error(f"Prompt '{request.params.name}' not found")
        return types.GetPromptResult(messages=[{"role": "system", "content": {"type": "text", "text": "Prompt not found"}}])
    try:
        messages = prompt.messages(request.params.arguments or {})
        logger.debug(f"Generated messages: {messages}")
        return types.GetPromptResult(messages=messages)
    except Exception as e:
        logger.error(f"Error generating prompt: {e}", exc_info=True)
        return types.GetPromptResult(messages=[{"role": "system", "content": {"type": "text", "text": f"Prompt error: {str(e)}"}}])

def register_functions(spec: Dict) -> List[types.Tool]:
    """Register tools from OpenAPI spec, preserving across calls if already populated."""
    global tools
    logger.debug("Clearing previously registered tools to allow re-registration")
    tools.clear()
    if not spec:
        logger.error("OpenAPI spec is None or empty.")
        return tools
    if 'paths' not in spec:
        logger.error("No 'paths' key in OpenAPI spec.")
        return tools
    logger.debug(f"Spec paths available: {list(spec['paths'].keys())}")
    filtered_paths = {path: item for path, item in spec['paths'].items() if is_tool_whitelisted(path)}
    filtered_paths = {path: item for path, item in spec['paths'].items() if is_tool_whitelist_exact(path)}
    logger.debug(f"Filtered paths: {list(filtered_paths.keys())}")
    if not filtered_paths:
        logger.warning("No whitelisted paths found in OpenAPI spec after filtering.")
        return tools
    for path, path_item in filtered_paths.items():
        if not path_item:
            logger.debug(f"Empty path item for {path}")
            continue
        for method, operation in path_item.items():
            if method.lower() not in ['get', 'post', 'put', 'delete', 'patch']:
                logger.debug(f"Skipping unsupported method {method} for {path}")
                continue
            try:
                raw_name = f"{method.upper()} {path}"
                function_name = normalize_tool_name(raw_name)
                description = operation.get('summary', operation.get('description', 'No description available'))
                input_schema = {
                    "type": "object",
                    "properties": {},
                    "required": [],
                    "additionalProperties": False
                }
                parameters = operation.get('parameters', [])
                placeholder_params = [part.strip('{}') for part in path.split('/') if '{' in part and '}' in part]
                for param_name in placeholder_params:
                    input_schema['properties'][param_name] = {
                        "type": "string",
                        "description": f"Path parameter {param_name}"
                    }
                    input_schema['required'].append(param_name)
                    logger.debug(f"Added URI placeholder {param_name} to inputSchema for {function_name}")
                for param in parameters:
                    param_name = param.get('name')
                    param_in = param.get('in')
                    if param_in in ['path', 'query']:
                        param_type = param.get('schema', {}).get('type', 'string')
                        schema_type = param_type if param_type in ['string', 'integer', 'boolean', 'number'] else 'string'
                        input_schema['properties'][param_name] = {
                            "type": schema_type,
                            "description": param.get('description', f"{param_in} parameter {param_name}"),
                            "default": param.get("schema", {}).get("default", None),
                        }
                        if param.get('required', False) and param_name not in input_schema['required']:
                            input_schema['required'].append(param_name)
                tool = types.Tool(
                    name=function_name,
                    description=description,
                    inputSchema=input_schema,
                )
                tools.append(tool)
                logger.debug(f"Registered function: {function_name} ({method.upper()} {path}) with inputSchema: {json.dumps(input_schema)}")

                api_resp_json_path_mapping = parse_api_resp_json_path()
                resp_json_path = api_resp_json_path_mapping[path]
                global function_name_resp_json_path_mapping
                function_name_resp_json_path_mapping[function_name] = resp_json_path

            except Exception as e:
                logger.error(f"Error registering function for {method.upper()} {path}: {e}", exc_info=True)
    logger.debug(f"API response JSON path mapping: {function_name_resp_json_path_mapping}")
    logger.debug(f"Registered {len(tools)} functions from OpenAPI spec.")
    return tools

def lookup_operation_details(function_name: str, spec: Dict) -> Dict or None:
    if not spec or 'paths' not in spec:
        return None
    for path, path_item in spec['paths'].items():
        for method, operation in path_item.items():
            if method.lower() not in ['get', 'post', 'put', 'delete', 'patch']:
                continue
            raw_name = f"{method.upper()} {path}"
            current_function_name = normalize_tool_name(raw_name)
            if current_function_name == function_name:
                return {"path": path, "method": method.upper(), "operation": operation, "original_path": path}
    return None
