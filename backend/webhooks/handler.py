from backend.database.database import SessionLocal
from backend.models.models import Order
from backend.utils.logger import get_transaction_logger, log_audit_trail, get_error_logger

logger = get_transaction_logger()
error_logger = get_error_logger()

def handle_payment_success(payment_intent):
    order_id = payment_intent['metadata'].get('order_id')
    
    if not order_id:
        logger.warning("Payment success but no order_id in metadata")
        return
    
    # Update order status
    db = SessionLocal()
    try:
        order = db.query(Order).filter(Order.id == int(order_id)).first()
        if order:
            order.status = "SUCCESS"
            db.commit()
            
            log_audit_trail(
                action='order_completed',
                actor_user_id='stripe_webhook',
                target=f'order:{order_id}',
                details={'transaction_id': payment_intent['id']}
            )
            
            logger.info(
                "Order updated from webhook",
                extra={'order_id': order_id, 'transaction_id': payment_intent['id']}
            )
    except Exception as e:
        logger.error(f"Failed to update order {order_id}", exc_info=True)
        db.rollback()
    finally:
        db.close()
    
def handle_payment_method_attached(payment_method):
    # xu li khi phuong thuc thanh toan moi duoc gan vao khach hang
    print(f"Da gan phuong thuc thanh toan {payment_method['id']}")
    
def handle_unhandle_event(event_type):
    print(f"Bo qua su kien khong xu li: {event_type}")
    
def dispatch_event(event):
    
    #dieu phoi su kien da duoc xac thuc den ham xu li
    try:
        event_type = event.get('type')
        event_data = event.get('data', {}).get('object')
    except Exception as e:
        error_logger.error(f"Error parsing event: {str(e)}", exc_info=True)
        return {"status": "error", "message": str(e)}
        
    if event_type == 'payment_intent.succeeded':
        handle_payment_success(event_data)
        
    elif event_type == 'payment_method.attached':
        handle_payment_method_attached(event_data)
    else:
        handle_unhandle_event(event_type)
        
    return {"status": "success"}
