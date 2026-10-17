import re

FILE_PATH = r"d:\DEEPTRUST PROJECT 2026\deeptrust\DEEEPTRUST.02\server\ai_service\face_service.py"

with open(FILE_PATH, "r", encoding="utf-8") as f:
    content = f.read()

# Fix broken multi-line defs
content = re.sub(r'def get_monthly_security_report\(user: dict = Depends\(get_authenticated_user_from_header\)\n\s+if user.get\("role"\) not in \["DEEPTRUST_OWNER", "DEEPTRUST_ADMIN"\]:\n\s+raise HTTPException\(status_code=403, detail="Forbidden: Requires DeepTrust Platform Admin privileges."\)\n\s+year: int = 2026,\n\s+month: int = 9,\n\s+download: bool = False,\n\s+authorization: Optional\[str\] = Header\(None\)\n\):', 
r'''def get_monthly_security_report(
    year: int = 2026,
    month: int = 9,
    download: bool = False,
    authorization: Optional[str] = Header(None),
    user: dict = Depends(get_authenticated_user_from_header)
):
    if user.get("role") not in ["DEEPTRUST_OWNER", "DEEPTRUST_ADMIN"]:
        raise HTTPException(status_code=403, detail="Forbidden: Requires DeepTrust Platform Admin privileges.")''', content)

with open(FILE_PATH, "w", encoding="utf-8") as f:
    f.write(content)

print("Fixed get_monthly_security_report syntax error.")
