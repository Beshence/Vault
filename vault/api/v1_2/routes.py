from fastapi import APIRouter, HTTPException

router = APIRouter()

@router.post("/create_user")
def create_user():
    return {"info": "changed in v1.2"}

@router.get("/get_user", include_in_schema=False)
def get_user():
    raise HTTPException(status_code=410, detail="this endpoint was deleted at v1.2")