# api.py
# Security Service Server (Punk Records)
# Mendukung Variasi Cipher (Ed25519 & EC-SECP256K1)

from fastapi import FastAPI, HTTPException, UploadFile, File, Form, Body
from fastapi.middleware.cors import CORSMiddleware
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ed25519, ec
import os
from datetime import datetime

# Penamaan sesuai permintaan
app = FastAPI(title="Security Service", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- KONFIGURASI KUNCI OTORITAS SERVER ---
# Server menggunakan kunci Ed25519 (priv19) sebagai identitas utama
priv_key_path = "punkhazard-keys/priv19.pem"
pub_key_path = "punkhazard-keys/pub19.pem"

server_priv_key = None

# Database in-memory
users_db = {} 
message_box = {}

# --- FUNGSI LOAD KUNCI SERVER ---
if os.path.exists(priv_key_path):
    with open(priv_key_path, "rb") as f:
        server_priv_key = serialization.load_pem_private_key(f.read(), password=None)
    print(f"[INFO] Server Authority Key Loaded from {priv_key_path}")
else:
    print("[WARNING] Kunci Server tidak ditemukan.")

# --- HELPER: SMART VERIFICATION (VARIASI CIPHER) ---
def verify_smart_signature(public_key, signature_bytes, data_bytes):
    """
    Mendeteksi jenis algoritma kunci (EC atau Ed25519) dan melakukan verifikasi yang sesuai.
    """
    try:
        if isinstance(public_key, ed25519.Ed25519PublicKey):
            # Algoritma 1: Ed25519
            public_key.verify(signature_bytes, data_bytes)
        elif isinstance(public_key, ec.EllipticCurvePublicKey):
            # Algoritma 2: Elliptic Curve (SECP256K1) - Butuh Hash SHA256
            public_key.verify(signature_bytes, data_bytes, ec.ECDSA(hashes.SHA256()))
        else:
            raise Exception("Algoritma kunci tidak didukung.")
    except Exception as e:
        raise e 

# --- ENDPOINTS ---

@app.get("/")
async def index():
    return {"message": "Security Service is running", "users_registered": len(users_db)}

@app.get("/health")
async def health_check():
    return {
        "status": "Security Service is running",
        "timestamp": datetime.now().isoformat()
    }

# 1. Endpoint Simpan Public Key (Mendukung Variasi Cipher)
@app.post("/store")
async def store_pubkey(username: str = Form(...), file: UploadFile = File(...)):
    try:
        key_content = await file.read()
        
        # Load Key (Auto-detect format)
        public_key = serialization.load_pem_public_key(key_content)
        
        # Deteksi nama algoritma untuk laporan
        algo_name = "Unknown"
        if isinstance(public_key, ed25519.Ed25519PublicKey):
            algo_name = "Ed25519"
        elif isinstance(public_key, ec.EllipticCurvePublicKey):
            algo_name = "EC (SECP256K1)"
            
        users_db[username] = public_key
        
        return {
            "status": "success", 
            "message": f"Public Key user '{username}' berhasil disimpan.",
            "algorithm": algo_name # Bukti variasi cipher
        }
    except Exception as e:
        return {"status": "error", "message": f"Format Key Invalid: {str(e)}"}

# 2. Endpoint Verifikasi Pesan
@app.post("/verify")
async def verify(username: str = Body(...), message: str = Body(...), signature_hex: str = Body(...)):
    if username not in users_db:
        raise HTTPException(status_code=404, detail="User tidak ditemukan.")
    
    try:
        pub_key = users_db[username]
        sig_bytes = bytes.fromhex(signature_hex)
        msg_bytes = message.encode('utf-8')
        
        # Panggil fungsi pintar
        verify_smart_signature(pub_key, sig_bytes, msg_bytes)
        
        return {"verified": True, "message": "Signature VALID. Pesan asli."}
    except Exception:
        return {"verified": False, "message": "Signature INVALID!"}

# 3. Endpoint Upload PDF dengan Integrity Check & Server Receipt
@app.post("/upload-pdf")
async def upload_pdf(
    username: str = Form(...), 
    signature_hex: str = Form(...), 
    file: UploadFile = File(...)
):
    fname = file.filename
    if username not in users_db:
        raise HTTPException(status_code=404, detail="User belum register key.")

    try:
        content = await file.read()
        user_pub_key = users_db[username]
        sig_bytes = bytes.fromhex(signature_hex)
        
        # A. Integrity Check (User Signature)
        verify_smart_signature(user_pub_key, sig_bytes, content)
        
        # B. Server Signing (Receipt)
        server_receipt = "ServerKeyMissing"
        if server_priv_key:
            # Server menandatangani bukti terima
            receipt_msg = f"RECEIVED:{fname}:{username}".encode()
            server_receipt = server_priv_key.sign(receipt_msg).hex()
        
        # Simpan File
        os.makedirs("uploads", exist_ok=True)
        with open(f"uploads/{username}_{fname}", "wb") as f:
            f.write(content)
            
        return {
            "verified": True, 
            "message": "Integrity Check PASSED. File aman.",
            "filename": fname,
            "server_receipt_signature": server_receipt
        }
    except Exception as e:
        return {"verified": False, "message": f"Integrity Check FAILED: {str(e)}"}

# 4. Endpoint Relay Pesan
@app.post("/relay")
async def relay(sender: str = Body(...), recipient: str = Body(...), message_content: str = Body(...)):
    if recipient not in message_box: message_box[recipient] = []
    message_box[recipient].append({"from": sender, "msg": message_content, "time": datetime.now().isoformat()})
    return {"status": "delivered", "recipient": recipient}