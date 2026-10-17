import requests
import time
import threading
import socket
import re
from pymongo import MongoClient

captured_emails = []

def start_smtp_socket():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(('127.0.0.1', 1025))
    server.listen(1)
    while True:
        conn, addr = server.accept()
        conn.sendall(b"220 mock-smtp\r\n")
        email_data = b""
        in_data = False
        while True:
            line = conn.recv(1024)
            if not line:
                break
            line_str = line.decode('utf-8', errors='ignore')
            if line_str.startswith("EHLO") or line_str.startswith("HELO"):
                conn.sendall(b"250 Hello\r\n")
            elif line_str.startswith("AUTH"):
                conn.sendall(b"235 Ok\r\n")
            elif line_str.startswith("MAIL FROM:"):
                conn.sendall(b"250 Ok\r\n")
            elif line_str.startswith("RCPT TO:"):
                conn.sendall(b"250 Ok\r\n")
            elif line_str.startswith("DATA"):
                conn.sendall(b"354 End data with <CR><LF>.<CR><LF>\r\n")
                in_data = True
            elif line_str.startswith("QUIT"):
                conn.sendall(b"221 Bye\r\n")
                break
            elif in_data:
                email_data += line
                if b"\r\n.\r\n" in email_data:
                    captured_emails.append(email_data.decode('utf-8', errors='ignore'))
                    conn.sendall(b"250 Ok\r\n")
                    in_data = False

smtp_thread = threading.Thread(target=start_smtp_socket, daemon=True)
smtp_thread.start()
time.sleep(1)

API_URL = "http://localhost:8000/api/v1"

def print_result(test_name, expected, actual_status, passed):
    print(f"{test_name}: {'PASS' if passed else 'FAIL'} (Expected: {expected}, Got: {actual_status})")

def extract_otp(email_data):
    # Regex to find 6 digit number
    match = re.search(r'\b(\d{6})\b', email_data)
    if match:
        return match.group(1)
    return None

def run_tests():
    print("Running Email Verification Tests...")
    email = f"test_{int(time.time())}@healthcare.demo"
    
    # 1. Send Code
    captured_emails.clear()
    r = requests.post(f"{API_URL}/auth/email/send-code", json={"email": email})
    print_result("TEST EMAIL-1: Email Provider Working (Local)", "200", r.status_code, r.status_code == 200)
    
    time.sleep(2)
    if not captured_emails:
        print("FAIL: No email captured by mock SMTP.")
        return
    
    otp_code_1 = extract_otp(captured_emails[-1])
    print(f"Captured OTP: {otp_code_1}")
    
    # TEST EMAIL-3: Enter wrong code
    r_wrong = requests.post(f"{API_URL}/auth/email/verify-code", json={"email": email, "code": "000000"})
    print_result("TEST EMAIL-3: Enter wrong code", "400", r_wrong.status_code, r_wrong.status_code == 400 and "EMAIL_OTP_INVALID" in r_wrong.text)
    
    # TEST EMAIL-4: Expired code (mock in db)
    client = MongoClient("mongodb://localhost:27017/")
    db = client.deeptrust
    db.email_verifications.update_one({"email": email}, {"$set": {"expires_at": time.time() - 100}})
    r_expired = requests.post(f"{API_URL}/auth/email/verify-code", json={"email": email, "code": otp_code_1})
    print_result("TEST EMAIL-4: Use expired code", "400", r_expired.status_code, r_expired.status_code == 400 and "EMAIL_OTP_EXPIRED" in r_expired.text)
    
    # Restore expiry
    db.email_verifications.update_one({"email": email}, {"$set": {"expires_at": time.time() + 600}})
    
    # TEST EMAIL-8: Exceed resend/attempt policy (limit is 5)
    for _ in range(3):
        requests.post(f"{API_URL}/auth/email/verify-code", json={"email": email, "code": "000000"})
    r_limit = requests.post(f"{API_URL}/auth/email/verify-code", json={"email": email, "code": "000000"})
    print_result("TEST EMAIL-8: Exceed attempt policy", "429", r_limit.status_code, r_limit.status_code == 429 and "EMAIL_ATTEMPTS_EXCEEDED" in r_limit.text)
    
    # TEST EMAIL-5: Request resend (cooldown is 60s, we will bypass it in DB to test)
    db.email_verifications.update_one({"email": email}, {"$set": {"created_at": time.time() - 65, "attempt_count": 0}})
    captured_emails.clear()
    r_resend = requests.post(f"{API_URL}/auth/email/resend-code", json={"email": email})
    print_result("TEST EMAIL-5: Request resend", "200", r_resend.status_code, r_resend.status_code == 200)
    
    time.sleep(2)
    otp_code_2 = extract_otp(captured_emails[-1])
    
    # TEST EMAIL-6: Test previous code after resend
    r_old = requests.post(f"{API_URL}/auth/email/verify-code", json={"email": email, "code": otp_code_1})
    print_result("TEST EMAIL-6: Test previous code after resend", "400", r_old.status_code, r_old.status_code == 400 and "EMAIL_OTP_INVALID" in r_old.text)
    
    # TEST EMAIL-2: Enter correct code
    r_correct = requests.post(f"{API_URL}/auth/email/verify-code", json={"email": email, "code": otp_code_2})
    print_result("TEST EMAIL-2: Enter correct code", "200", r_correct.status_code, r_correct.status_code == 200)
    
    # TEST EMAIL-7: Reuse already consumed OTP
    r_reuse = requests.post(f"{API_URL}/auth/email/verify-code", json={"email": email, "code": otp_code_2})
    print_result("TEST EMAIL-7: Reuse already consumed OTP", "400", r_reuse.status_code, r_reuse.status_code == 400 and "EMAIL_OTP_ALREADY_USED" in r_reuse.text)
    
    # Test Email failure handling
    db.email_verifications.delete_many({"email": email})

if __name__ == "__main__":
    run_tests()
