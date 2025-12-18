# client.py
# Client Utility Tool - Mendukung Multi-Algorithm

import os
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ed25519, ec

# --- KONFIGURASI PENGGUNA (GANTI INI SAAT DEMO) ---
# 1 = Menggunakan kunci Ed25519 (priv19.pem)
# 2 = Menggunakan kunci EC (priv.pem) -> VARIASI CIPHER
PILIHAN_USER = 2

if PILIHAN_USER == 1:
    user_alias = "Fawazul_ED"
    priv_key_path = "punkhazard-keys/priv19.pem"
    pub_key_path = "punkhazard-keys/pub19.pem"
    algo_label = "Ed25519"
else:
    user_alias = "Fawazul_EC"
    priv_key_path = "punkhazard-keys/priv.pem"
    pub_key_path = "punkhazard-keys/pub.pem"
    algo_label = "EC (SECP256K1)"

target_pdf_name = "Soal-UAS-KID25.pdf"

# --- FUNGSI LOAD KEY ---
def load_keys():
    print(f"--- MODE: {algo_label} ({user_alias}) ---")
    if not os.path.exists(priv_key_path):
        print(f"[ERROR] File {priv_key_path} tidak ditemukan.")
        return None, None

    with open(priv_key_path, "rb") as f:
        priv_obj = serialization.load_pem_private_key(f.read(), password=None)
    with open(pub_key_path, "rb") as f:
        pub_obj = serialization.load_pem_public_key(f.read())
        
    return priv_obj, pub_obj

# --- FUNGSI SIGNING SMART ---
def sign_data_smart(data_bytes, private_key):
    """Membuat signature sesuai jenis kunci"""
    if isinstance(private_key, ed25519.Ed25519PrivateKey):
        return private_key.sign(data_bytes).hex()
    elif isinstance(private_key, ec.EllipticCurvePrivateKey):
        return private_key.sign(data_bytes, ec.ECDSA(hashes.SHA256())).hex()
    return None

# --- MAIN ---
if __name__ == "__main__":
    priv_key, pub_key = load_keys()

    if priv_key:
        print("\n" + "="*50)
        print(f" DATA UNTUK INPUT KE SWAGGER UI")
        print("="*50)

        # 1. STORE
        print(f"\n[1] Endpoint /store")
        print(f"    File Upload : {pub_key_path}")
        print(f"    Username    : {user_alias}")
        print(f"    (Sistem akan mendeteksi: {algo_label})")

        # 2. VERIFY
        pesan = "Cek Keamanan Data"
        sig_pesan = sign_data_smart(pesan.encode(), priv_key)
        print(f"\n[2] Endpoint /verify")
        print(f"    Username      : {user_alias}")
        print(f"    Message       : {pesan}")
        print(f"    Signature Hex : {sig_pesan}")

        # 3. UPLOAD PDF
        if os.path.exists(target_pdf_name):
            with open(target_pdf_name, "rb") as f:
                sig_pdf = sign_data_smart(f.read(), priv_key)
            print(f"\n[3] Endpoint /upload-pdf")
            print(f"    Username      : {user_alias}")
            print(f"    File          : {target_pdf_name}")
            print(f"    Signature Hex : {sig_pdf}")
            print("\n    (Upload file PDF yang SAMA persis)")
        else:
            print(f"[WARN] File {target_pdf_name} tidak ditemukan.")