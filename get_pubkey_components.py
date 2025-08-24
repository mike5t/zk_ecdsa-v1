#!/usr/bin/env python3
"""
Script to derive public key x and y components from a private key
"""

from eth_keys import keys
from eth_utils import to_hex

def get_pubkey_components(private_key_hex):
    """
    Extract x and y components from a private key
    """
    # Remove 0x prefix if present
    if private_key_hex.startswith('0x'):
        private_key_hex = private_key_hex[2:]
    
    # Create private key object
    private_key = keys.PrivateKey(bytes.fromhex(private_key_hex))
    
    # Get the public key
    public_key = private_key.public_key
    
    # The uncompressed public key is 64 bytes (32 bytes x + 32 bytes y)
    # We need to get the raw bytes without the 0x04 prefix
    pubkey_bytes = public_key.to_bytes()
    
    # Split into x and y components (32 bytes each)
    x_bytes = pubkey_bytes[:32]
    y_bytes = pubkey_bytes[32:]
    
    # Convert to hex
    x_hex = to_hex(x_bytes)
    y_hex = to_hex(y_bytes)
    
    return x_hex, y_hex, to_hex(pubkey_bytes)

if __name__ == "__main__":
    private_key = "0xc145038b2e80667f01d45ab69163d6f4570f8c6a6cde6c74d2b36571621281f1"
    
    x, y, full_pubkey = get_pubkey_components(private_key)
    
    print("Private Key:", private_key)
    print("Full Public Key (64 bytes):", full_pubkey)
    print("X Component (32 bytes):", x)
    print("Y Component (32 bytes):", y)
    print()
    print("For use in your ZK circuit:")
    print("pub_key_x =", x)
    print("pub_key_y =", y)
