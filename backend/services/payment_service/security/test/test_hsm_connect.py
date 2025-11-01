import pkcs11

lib = pkcs11.lib(r"D:\SoftHSM2\lib\softhsm2-x64.dll")
token = lib.get_token(token_label='MyToken1')

with token.open(user_pin='890844') as session:
    print("✅ Connected to token:", token.label)
    # Liệt kê các object (nếu có)
    for obj in session.get_objects():
        print("🔹", obj)
