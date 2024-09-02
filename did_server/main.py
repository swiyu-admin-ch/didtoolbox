from fastapi import FastAPI, Depends, Response, status, File
from fastapi.security import APIKeyHeader
from typing import Annotated
from bindings.python import didtoolbox as toolbox
import uvicorn

app = FastAPI(title="DID Server")
api_key_header = APIKeyHeader(name="X-API-Key")

registry = dict()

@app.post("/{uuid}/did.jsonl", description="Save DID tdw lines for a given SCID")
async def save_did_lines(response: Response, uuid: str,  file: Annotated[bytes, File()], api_key: str = Depends(api_key_header)):
    if api_key != "secret":
        response.status_code = status.HTTP_403_FORBIDDEN
        return {"status": "invalid api key"}
    try:
        response.status_code = status.HTTP_201_CREATED
        
        # Validate entire did.jsonl file before storing it
        doc_state = toolbox.DidDocumentState._from(file.decode())
        did_doc = doc_state.validate()
        
        registry[uuid] = file
        return did_doc
    except Exception as e:
        response.status_code = status.HTTP_400_BAD_REQUEST
        return {"msg": "Validation of did.jsonl failed", "error": str(e)}


@app.get("/{uuid}/did.jsonl", description="Get DID tdw lines for a given SCID")
async def get_did_lines(response: Response, uuid: str):
    if uuid not in registry:
        response.status_code = status.HTTP_404_NOT_FOUND
        return {"status": f"SCID {uuid} not found"}
    return registry[uuid]


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)