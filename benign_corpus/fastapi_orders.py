"""FastAPI handler with Pydantic validation and parameterized queries."""
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from .db import get_session
from .models import Order

router = APIRouter(prefix="/orders", tags=["orders"])


class OrderCreate(BaseModel):
    item_id: int = Field(gt=0)
    quantity: int = Field(gt=0, le=1000)


@router.post("/", response_model=dict)
def create_order(payload: OrderCreate, session: Session = Depends(get_session)):
    order = Order(item_id=payload.item_id, quantity=payload.quantity)
    session.add(order)
    session.commit()
    session.refresh(order)
    return {"id": order.id, "status": "created"}


@router.get("/{order_id}", response_model=dict)
def get_order(order_id: int, session: Session = Depends(get_session)):
    order = session.query(Order).filter(Order.id == order_id).first()
    if order is None:
        raise HTTPException(status_code=404, detail="not found")
    return {"id": order.id, "item_id": order.item_id, "quantity": order.quantity}
