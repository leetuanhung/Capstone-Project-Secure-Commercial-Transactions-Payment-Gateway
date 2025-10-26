from backend.services.security.encryption import encrypt_field, decrypt_field
from backend.services.security.tokenization import tokenize_card, detokenize

def main():
    card_number = input("Nhập số thẻ: ").strip()
    token = tokenize_card(card_number)
    print("[+] Token hóa:", token)

    encrypted = encrypt_field(card_number, aad=token)  # include token as AAD (optional)
    print("[+] Mã hóa (base64):", encrypted)

    decrypted = decrypt_field(encrypted, aad=token)
    print("[+] Giải mã:", decrypted)

    original = detokenize(token)
    print("[+] Detokenize returns (internal store):", original)

if __name__ == "__main__":
    main()
