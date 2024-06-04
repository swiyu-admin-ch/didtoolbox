from fastapi import FastAPI, Depends, Response, status, File
from fastapi.security import APIKeyHeader
from typing import Annotated

app = FastAPI(title="DID Server")
api_key_header = APIKeyHeader(name="X-API-Key")

registry = dict()

@app.post("/{scid}/did.json", description="Save DID tdw lines for a given SCID")
async def save_did_lines(response: Response, scid: str,  file: Annotated[bytes, File()], api_key: str = Depends(api_key_header)):
    if api_key != "secret":
        response.status_code = status.HTTP_403_FORBIDDEN
        return {"status": "invalid api key"}
    response.status_code = status.HTTP_201_CREATED
    registry[scid] = file
    print(file.decode())
    return {"status": "ok"}


@app.get("/{scid}/did.json", description="Get DID tdw lines for a given SCID")
async def get_did_lines(response: Response, scid: str):
    if scid not in registry:
        response.status_code = status.HTTP_404_NOT_FOUND
        return {"status": f"SCID {scid} not found"}
    return registry[scid]
