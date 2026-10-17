import os
import sys
import json
import datetime
from bson import json_util
import pymongo

def run_backup(backup_dir=None):
    try:
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        if not backup_dir:
            project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
            backups_base = os.path.join(project_root, "backups")
            os.makedirs(backups_base, exist_ok=True)
            backup_dir = os.path.join(backups_base, f"deeptrust_backup_{timestamp}")

        os.makedirs(backup_dir, exist_ok=True)
        print(f"[*] Starting DeepTrust Database Backup...")
        print(f"[*] Backup Destination: {backup_dir}")

        client = pymongo.MongoClient("mongodb://localhost:27017/", serverSelectionTimeoutMS=3000)
        client.admin.command('ping')
        
        db = client["deeptrust"]
        collections = db.list_collection_names()

        if not collections:
            print("[!] Warning: Database 'deeptrust' contains no collections.")

        total_docs = 0
        for col_name in collections:
            docs = list(db[col_name].find({}))
            file_path = os.path.join(backup_dir, f"{col_name}.json")
            with open(file_path, "w", encoding="utf-8") as f:
                f.write(json_util.dumps(docs, indent=2))
            print(f"  [+] Dumped collection '{col_name}': {len(docs)} documents -> {os.path.basename(file_path)}")
            total_docs += len(docs)

        summary_path = os.path.join(backup_dir, "backup_manifest.json")
        manifest = {
            "timestamp": timestamp,
            "database": "deeptrust",
            "collections_backed_up": collections,
            "total_documents": total_docs
        }
        with open(summary_path, "w", encoding="utf-8") as f:
            json.dump(manifest, f, indent=2)

        print(f"[OK] Backup completed successfully. {len(collections)} collections ({total_docs} documents) backed up.")
        return True, backup_dir
    except Exception as e:
        print(f"[X] Backup failed: {str(e)}")
        return False, str(e)

if __name__ == "__main__":
    success, _ = run_backup()
    sys.exit(0 if success else 1)
