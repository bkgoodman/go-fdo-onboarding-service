#!/usr/bin/env python3
"""
Example HSM Voucher Signing Handler
Demonstrates JSON-based voucher signing for external HSM integration
"""

import json
import sys
import base64
import cbor
import logging
import time
from datetime import datetime

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class ExampleHSMSigner:
    """Example HSM signer that simulates HSM operations"""
    
    def __init__(self):
        self.key_id = "example-hsm-key-12345"
        self.hsm_id = "example-hsm-01"
    
    def sign_voucher(self, voucher, owner_key_pem):
        """Simulate HSM voucher signing"""
        logger.info(f"HSM: Signing voucher with key {self.key_id}")
        logger.info(f"HSM: Owner key type: {type(owner_key_pem)}")
        
        # In a real implementation, this would:
        # 1. Validate the voucher structure
        # 2. Use the HSM to sign the voucher with the owner key
        # 3. Return the signed voucher
        
        # For demo purposes, we'll just return the voucher unchanged
        # In production, this would be actual HSM signing
        logger.info("HSM: Simulating signing operation...")
        time.sleep(0.1)  # Simulate HSM processing time
        
        return voucher

def main():
    """Main handler function"""
    if len(sys.argv) < 2:
        response = {
            "signed_voucher": "",
            "request_id": "",
            "hsm_info": {},
            "error": "Missing request file argument"
        }
        print(json.dumps(response, indent=2))
        sys.exit(1)
    
    request_file = sys.argv[1]
    
    try:
        # Initialize HSM signer
        hsm_signer = ExampleHSMSigner()
        
        # Read JSON request
        with open(request_file, 'r') as f:
            request_data = json.load(f)
        
        # Validate required fields
        required_fields = ['voucher', 'owner_key', 'request_id']
        if not all(field in request_data for field in required_fields):
            response = {
                "signed_voucher": "",
                "request_id": request_data.get('request_id', ''),
                "hsm_info": {},
                "error": f"Missing required fields: {', '.join(required_fields)}"
            }
            print(json.dumps(response, indent=2))
            sys.exit(1)
        
        # Log request details
        request_id = request_data['request_id']
        logger.info(f"Received signing request: {request_id}")
        logger.info(f"Station: {request_data.get('manufacturing_station', 'unknown')}")
        logger.info(f"Device: {request_data.get('device_info', {}).get('serialno', 'unknown')}")
        
        # Decode voucher from base64
        voucher_data = base64.b64decode(request_data['voucher'])
        voucher = cbor.loads(voucher_data)
        
        # Sign with HSM
        start_time = time.time()
        signed_voucher = hsm_signer.sign_voucher(voucher, request_data['owner_key'])
        signing_time = time.time() - start_time
        
        # Create success response
        response = {
            "signed_voucher": base64.b64encode(cbor.dumps(signed_voucher)).decode(),
            "request_id": request_id,
            "hsm_info": {
                "hsm_id": hsm_signer.hsm_id,
                "signing_time": datetime.utcnow().isoformat(),
                "key_id": hsm_signer.key_id,
                "signing_duration_ms": int(signing_time * 1000)
            },
            "error": ""
        }
        
        logger.info(f"Successfully signed voucher {request_id} in {signing_time:.3f}s")
        print(json.dumps(response, indent=2))
        
    except Exception as e:
        # Create error response
        logger.error(f"Error processing request: {str(e)}")
        response = {
            "signed_voucher": "",
            "request_id": "",
            "hsm_info": {},
            "error": str(e)
        }
        print(json.dumps(response, indent=2))
        sys.exit(1)

if __name__ == '__main__':
    main()
