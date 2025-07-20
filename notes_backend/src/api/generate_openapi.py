import json
import os
import sys

# Adjust sys.path for imports if run from project root
sys.path.append(os.path.join(os.path.dirname(__file__), ".."))

from src.api.main import app

"""
Script to generate the OpenAPI schema from the FastAPI app and write it to interfaces/openapi.json.
Make sure to run this after updating endpoints to keep docs in sync.
"""

# Generate OpenAPI schema including all tags, summaries, request/response models
openapi_schema = app.openapi()

# Ensure output directory exists
output_dir = os.path.join(os.path.dirname(__file__), "../../interfaces")
os.makedirs(output_dir, exist_ok=True)
output_path = os.path.join(output_dir, "openapi.json")

with open(output_path, "w") as f:
    json.dump(openapi_schema, f, indent=2)

print(f"OpenAPI schema generated at {output_path}")
