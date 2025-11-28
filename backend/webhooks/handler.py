from backend.schemas import payment


def handle_payment_sucess(payment_intent):
    # xu li khi thanh toan thanh cong
    print(f"Thanh toan thanh cong, ID: {payment_intent['id']}")
    # cap nhat trang thai don hang
    # gui mail xac nhan
    
def handle_payment_method_attached(payment_method):
    # xu li khi phuong thuc thanh toan moi duoc gan vao khach hang
    print(f"Da gan phuong thuc thanh toan {payment_method['id']}")
    
def handle_unhandle_event(event_type):
    print(f"Bo qua su kien khong xu li: {event_type}")
    
def dispatch_event(event):
    
    #dieu phoi su kien da duoc xac thuc den ham xu li
    event_type = event['type']
    event_data = event['data']['object']
    
    if event_type == 'payment_intent.succeeded':
        handle_payment_sucess(event_data)
        
    elif event_type == 'payment_method.attached':
        handle_payment_method_attached(event_data)
    else:
        handle_unhandle_event(event_type)
        
    return {"status": "success"}
