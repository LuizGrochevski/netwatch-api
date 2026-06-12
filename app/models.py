from pydantic import BaseModel
from typing import List, Optional

class UserCreate(BaseModel):
    username: str
    password: str

class Token(BaseModel):
    access_token: str
    token_type: str

class ScanRequest(BaseModel):
    targets: List[str]

class ScanResponse(BaseModel):
    id: int
    targets: List[str]
    status: str
    results: Optional[dict] = None
    created_at: str
