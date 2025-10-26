import uuid
token_db = {}

def tokenize_card(card_number: str) -> str:
    token = str(uuid.uuid4())
    token_db[token] = card_number
    return token

def detokenize(token: str) -> str:
    return token_db.get(token, None)
