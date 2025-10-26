from backend.services.payment_service.security.tokenization import card_tokenizer


def setup_function():
    # Ensure a clean token vault before each test
    card_tokenizer.token_vault.clear()
    card_tokenizer.token_expiry.clear()


def test_tokenize_and_detokenize():
    card = "4111111111111111"
    result = card_tokenizer.generate_token(card, cvv="123", expiry="12/25", cardholder_name="JOHN DOE")
    assert isinstance(result, dict)
    token = result["token"]
    assert token.startswith("tok_")
    assert len(card_tokenizer.token_vault) == 1
    original = card_tokenizer.detokenize(token)
    assert original["card_number"] == card


def test_clear_token_database():
    card_tokenizer.token_vault.clear()
    card_tokenizer.token_expiry.clear()
    card_tokenizer.generate_token("4111111111111111", cvv="123", expiry="12/25", cardholder_name="A")
    assert len(card_tokenizer.token_vault) == 1
    card_tokenizer.token_vault.clear()
    card_tokenizer.token_expiry.clear()
    assert len(card_tokenizer.token_vault) == 0