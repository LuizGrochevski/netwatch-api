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
    ports: Optional[str] = "21,22,23,25,53,80,443,3306,5432,6379,8080"
    protocol: Optional[str] = "tcp"

class ScanResponse(BaseModel):
    id: int
    targets: List[str]
    status: str
    results: Optional[dict] = None
    created_at: str
