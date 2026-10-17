import re

FILE_PATH = r"d:\DEEPTRUST PROJECT 2026\deeptrust\DEEEPTRUST.02\server\ai_service\face_service.py"

with open(FILE_PATH, "r", encoding="utf-8") as f:
    lines = f.readlines()

in_admin_section = False
new_lines = []

for idx, line in enumerate(lines):
    if "14. DEEPTRUST PLATFORM ADMIN CONSOLE ENDPOINTS" in line:
        in_admin_section = True
        
    if in_admin_section:
        # Match function definition right after @app. decorator
        # Only if the previous line is @app.get/post/delete/etc with /api/v1/admin
        if line.startswith("def ") and idx > 0 and "/api/v1/admin/" in lines[idx-1]:
            # It's an admin endpoint!
            # Example: def get_admin_overview(): -> def get_admin_overview(user: dict = Depends(get_authenticated_user_from_header)):
            # Wait, some might already have arguments.
            
            # Change def foo(req: ...): to def foo(req: ..., user: dict = Depends(get_authenticated_user_from_header)):
            
            # Parse signature
            sig_start = line.find("(")
            sig_end = line.rfind(")")
            sig_content = line[sig_start+1:sig_end].strip()
            
            if "Depends(get_authenticated_user_from_header)" not in sig_content:
                if len(sig_content) > 0:
                    new_sig_content = sig_content + ", user: dict = Depends(get_authenticated_user_from_header)"
                else:
                    new_sig_content = "user: dict = Depends(get_authenticated_user_from_header)"
                
                line = line[:sig_start+1] + new_sig_content + line[sig_end:]
            
            new_lines.append(line)
            
            # Now add RBAC check right after the def line
            rbac_check = """    if user.get("role") not in ["DEEPTRUST_OWNER", "DEEPTRUST_ADMIN"]:
        raise HTTPException(status_code=403, detail="Forbidden: Requires DeepTrust Platform Admin privileges.")
"""
            new_lines.append(rbac_check)
            continue
            
    new_lines.append(line)

with open(FILE_PATH, "w", encoding="utf-8") as f:
    f.writelines(new_lines)

print("Applied RBAC fixes.")
