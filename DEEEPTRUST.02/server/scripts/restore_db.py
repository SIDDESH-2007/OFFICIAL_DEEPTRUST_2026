import os
import sys
import json
import argparse
from bson import json_util
import pymongo

def run_restore(backup_dir, target_db_name="deeptrust", force=False):
    if not os.path.exists(backup_dir):
        print(f"[X] Error: Backup directory not found: {backup_dir}")
        return False

    manifest_path = os.path.join(backup_dir, "backup_manifest.json")
    if not os.path.exists(manifest_path):
        print(f"[X] Error: Invalid backup directory. Manifest missing: {manifest_path}")
        return False

    with open(manifest_path, "r", encoding="utf-8") as f:
        manifest = json.load(f)

    print("==================================================")
    print(" DEEPTRUST DATABASE RESTORE PROCEDURE")
    print("==================================================")
    print(f" Source Backup:     {backup_dir}")
    print(f" Backup Timestamp:  {manifest.get('timestamp')}")
    print(f" Target Database:   {target_db_name}")
    print(f" Collections Count: {len(manifest.get('collections_backed_up', []))}")
    print("==================================================")

    if not force:
        confirm = input(f"[!] WARNING: This will overwrite data in database '{target_db_name}'. Type 'YES' to proceed: ")
        if confirm.strip() != "YES":
            print("[*] Restore cancelled by user.")
            return False

    try:
        client = pymongo.MongoClient("mongodb://localhost:27017/", serverSelectionTimeoutMS=3000)
        client.admin.command('ping')
        
        target_db = client[target_db_name]

        total_restored = 0
        for col_name in manifest.get("collections_backed_up", []):
            file_path = os.path.join(backup_dir, f"{col_name}.json")
            if not os.path.exists(file_path):
                print(f"[!] Warning: Missing collection backup file: {file_path}")
                continue

            with open(file_path, "r", encoding="utf-8") as f:
                docs = json_util.loads(f.read())

            target_db[col_name].drop()
            if docs:
                target_db[col_name].insert_many(docs)
            print(f"  [+] Restored collection '{col_name}': {len(docs)} documents")
            total_restored += len(docs)

        print(f"[OK] Restore successfully completed into '{target_db_name}'. ({total_restored} total documents)")
        return True
    except Exception as e:
        print(f"[X] Restore failed: {str(e)}")
        return False

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Restore DeepTrust MongoDB database.")
    parser.add_argument("--backup-dir", type=str, help="Path to backup directory")
    parser.add_argument("--target-db", type=str, default="deeptrust", help="Target DB name")
    parser.add_argument("--force", action="store_true", help="Bypass explicit prompt")
    args = parser.parse_args()

    if not args.backup_dir:
        # Find most recent backup if not specified
        project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        backups_base = os.path.join(project_root, "backups")
        if os.path.exists(backups_base):
            subdirs = [os.path.join(backups_base, d) for d in os.listdir(backups_base) if os.path.isdir(os.path.join(backups_base, d))]
            if subdirs:
                subdirs.sort(key=os.path.getmtime, reverse=True)
                args.backup_dir = subdirs[0]

    if not args.backup_dir:
        print("[×] Error: No backup directory specified and no backups found in backups/")
        sys.exit(1)

    success = run_restore(args.backup_dir, args.target_db, args.force)
    sys.exit(0 if success else 1)
