from typing import Optional
from pydantic import BaseModel, EmailStr, ConfigDict, Field
from datetime import datetime
from pydantic.types import conint

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    id: int