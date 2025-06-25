#!/usr/bin/env python3
"""
Minimal reproduction of ECR Public login issue with GitHub runners
Issue: client.login fails with 500 Server Error when using boto3 + docker-py
"""

import boto3
import docker
import base64

def login_to_ecr_public(region_name="us-east-1"):
    """Reproduce the failing ECR Public login"""
    try:
        # Get ECR Public authorization token
        ecr = boto3.client("ecr-public", region_name=region_name)
        response = ecr.get_authorization_token()
        
        # Extract and decode the token
        auth_token = response["authorizationData"]["authorizationToken"]
        
        # Attempt docker login (this is where it fails in GitHub runners)
        client = docker.from_env()
        login_response = client.login(
            username="AWS",
            password=auth_token,
            registry="public.ecr.aws"
        )
        print("[SUCCESS] Logged in to ECR Public:", login_response)
        return True
        
    except docker.errors.APIError as e:
        print(f"[ERROR] Docker API Error: {e}")
        return False
    except Exception as e:
        print(f"[ERROR] Unexpected error: {e}")
        return False

def debug_auth_token():
    """Debug the authorization token format"""
    try:
        ecr = boto3.client("ecr-public", region_name="us-east-1")
        response = ecr.get_authorization_token()
        auth_token = response["authorizationData"]["authorizationToken"]
        
        # Decode base64 token to see username:password format
        decoded = base64.b64decode(auth_token).decode('utf-8')
        username, password = decoded.split(':', 1)
        
        print(f"[DEBUG] Token username: {username}")
        print(f"[DEBUG] Token length: {len(password)}")
        print(f"[DEBUG] Registry endpoint: public.ecr.aws")
        
        return username, password
        
    except Exception as e:
        print(f"[ERROR] Failed to debug token: {e}")
        return None, None

if __name__ == "__main__":
    print("=== Reproducing ECR Public Login Issue ===")
    
    # Debug the auth token first
    print("\n1. Debugging authorization token...")
    username, password = debug_auth_token()
    
    # Attempt the failing login
    print("\n2. Attempting ECR Public login...")
    success = login_to_ecr_public()
    
    if not success:
        print("\n[INFO] Login failed - this reproduces the GitHub runner issue")
        print("[INFO] Error: 500 Server Error for http+docker://localhost/v1.48/auth")
        print("[INFO] Cause: login attempt to https://public.ecr.aws/v2/ failed with status: 400 Bad Request")