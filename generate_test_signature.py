#!/usr/bin/env python3

import hashlib
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA256
import binascii

def generate_emv_signature():
    # EMV test data (in order they appear in the packed format)
    arqc = bytes.fromhex("1234567890ABCDEF")  # 8 bytes
    unpredictable_number = bytes.fromhex("12345678")  # 4 bytes  
    atc = bytes.fromhex("0000")  # 2 bytes
    amount = bytes.fromhex("000000010000")  # 6 bytes
    currency = bytes.fromhex("0348")  # 2 bytes
    date = bytes.fromhex("231201")  # 3 bytes
    txn_type = bytes.fromhex("00")  # 1 byte
    tvr = bytes.fromhex("0000000000")  # 5 bytes
    cvm_results = bytes.fromhex("000000")  # 3 bytes
    terminal_id = bytes.fromhex("5445535430303100")  # 8 bytes "TEST001" padded
    merchant_id = bytes.fromhex("4D45524348414E5430303132333400")  # 15 bytes "MERCHANT001234" padded
    acquirer_id = bytes.fromhex("414351554952")  # 6 bytes "ACQUIR"
    
    # Assemble all EMV fields (63 bytes total)
    all_fields = (arqc + unpredictable_number + atc + amount + currency + 
                 date + txn_type + tvr + cvm_results + terminal_id + 
                 merchant_id + acquirer_id)
    
    print(f"All EMV fields length: {len(all_fields)} bytes")
    print(f"All EMV fields hex: {all_fields.hex()}")
    
    # Create Signed Data Format 3 structure
    header = bytes.fromhex("6A")
    format_byte = bytes.fromhex("03")
    trailer = bytes.fromhex("BC")
    
    dynamic_data = header + format_byte + all_fields + trailer
    print(f"Dynamic data length: {len(dynamic_data)} bytes")
    print(f"Dynamic data hex: {dynamic_data.hex()}")
    
    # Generate new RSA key pair (2048-bit for testing)
    key = RSA.generate(2048)
    
    # Create SHA-256 hash of dynamic data
    sha256_hash = SHA256.new(dynamic_data)
    
    # Sign using PKCS#1 v1.5
    signer = PKCS1_v1_5.new(key)
    signature = signer.sign(sha256_hash)
    
    print(f"Signature length: {len(signature)} bytes")
    print(f"Signature hex: {signature.hex()}")
    
    # Extract public key components
    public_key = key.publickey()
    modulus = public_key.n.to_bytes(256, 'big')  # 2048 bits = 256 bytes
    exponent = public_key.e.to_bytes(3, 'big')   # Usually 65537 = 0x010001
    
    print(f"Modulus length: {len(modulus)} bytes")
    print(f"Modulus hex: {modulus.hex()}")
    print(f"Exponent length: {len(exponent)} bytes") 
    print(f"Exponent hex: {exponent.hex()}")
    
    # Verify the signature
    verifier = PKCS1_v1_5.new(public_key)
    valid = verifier.verify(sha256_hash, signature)
    print(f"Signature verification: {valid}")
    
    return {
        'dynamic_data': dynamic_data.hex(),
        'signature': signature.hex(),
        'modulus': modulus.hex(),
        'exponent': exponent.hex(),
        'all_fields': all_fields.hex()
    }

if __name__ == "__main__":
    result = generate_emv_signature()
    
    print("\n=== Constants for Solidity test ===")
    print(f'bytes constant TEST_SIGNATURE = hex"{result["signature"]}";')
    print(f'bytes constant TEST_MODULUS = hex"{result["modulus"]}";')
    print(f'bytes constant TEST_EXPONENT = hex"{result["exponent"]}";')
    print(f'bytes constant EXPECTED_DYNAMIC_DATA = hex"{result["dynamic_data"]}";')
