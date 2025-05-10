from fastapi import APIRouter

router = APIRouter()

@router.get("/get_user")
def get_user():
    return {"info": "created in v1.0"}