import requests
import json
import uuid

# Configuration
# PROXY_URL = "http://192.168.139.146:3000"
PROXY_URL = "http://localhost:9090/filesystem/"
AUTH_TOKEN = "DefaultTokens" # Replace with the token from your config.json

def send_mcp_call(method, arguments):
    """Sends an MCP request and prints the response."""
    request_id = str(uuid.uuid4())
    payload = {
        "jsonrpc": "2.0",
        "id": request_id,
        "method": "tools/call",
        "params": {
            "name": method,
            "arguments": arguments,
        }
    }
    
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {AUTH_TOKEN}"
    }

    print(f"Sending request for method: {method}")
    try:
        response = requests.post(PROXY_URL, headers=headers, data=json.dumps(payload))
        response.raise_for_status()
        print(f"Response Status: {response.status_code}")
        try:
            json_response = response.json()
            print("Response Body:")
            print(json.dumps(json_response, indent=2))
        except json.JSONDecodeError:
            print(f"Response Body (not JSON):\n{response.text}")
    except requests.exceptions.RequestException as e:
        print(f"Request failed: {e}")
        if e.response is not None:
            print(f"Response status: {e.response.status_code}")
            try:
                json_response = e.response.json()
                print("Response Body:")
                print(json.dumps(json_response, indent=2))
            except json.JSONDecodeError:
                print(f"Response body (not JSON):\n{e.response.text}")

# Test 1: List a directory (should succeed with a valid policy)
# This assumes the mounted directory has content
print("--- Testing 'list_directory' (expected to succeed) ---")
send_mcp_call(
    method="list_directory",
    arguments={"path": "mcp_data"}
)
print("\n" + "="*50 + "\n")

# Test 2: Read a public file (should succeed as per policy)
print("--- Testing 'read_file' on public.txt (expected to succeed) ---")
send_mcp_call(
    method="read_file",
    arguments={
        "path": "mcp_data/public.txt"
    }
)
print("\n" + "="*50 + "\n")

# Test 3: Read a confidential file (should fail per policy)
print("--- Testing 'read_file' on confidential file (expected to fail) ---")
send_mcp_call(
    method="read_file",
    arguments={
        "path": "mcp_data/confidential.txt"
    }
)
print("\n" + "="*50 + "\n")

# Test 4: Write to a file (should fail as write_file not allowed in policy)
print("--- Testing 'write_file' (expected to fail) ---")
send_mcp_call(
    method="write_file",
    arguments={
        "path": "mcp_data/test_write.txt",
        "content": "This should be blocked by policy"  # Changed from 'contents' to 'content'
    }
)