from fastapi import APIRouter

router = APIRouter()

@router.post("/create_user")
def create_user():
    return {"info": "created in v1.1"}