from fastapi import FastAPI
from pydantic import BaseModel

class Item(BaseModel):
    name: str
    description: str | None = None
    price: float
    tax: float | None = None


app = FastAPI()


@app.get("/")
async def read_root() -> dict:
    return {"Hello": "World"}


@app.post("/items/")
async def create_item(item: Item) -> Item:
    return item