#!/usr/bin/env python3
import os, sqlite3, tarfile, tempfile, time

ROOT=os.path.dirname(os.path.abspath(__file__))
DB=os.environ.get("KEYCHAIN_DB",os.path.join(ROOT,"keychain.db"))
DEVICE_KEY=os.environ.get("KEYCHAIN_KEY",os.path.join(ROOT,".device-key"))
BACKUP_DIR=os.environ.get("KEYCHAIN_BACKUP_DIR",os.path.join(ROOT,"backups"))
KEEP=int(os.environ.get("KEYCHAIN_BACKUP_KEEP","14"))

def main():
    os.makedirs(BACKUP_DIR,mode=0o700,exist_ok=True); os.chmod(BACKUP_DIR,0o700)
    stamp=time.strftime("%Y%m%d-%H%M%S")
    fd,snapshot=tempfile.mkstemp(prefix=".snapshot-",suffix=".db",dir=BACKUP_DIR); os.close(fd)
    try:
        source=sqlite3.connect(f"file:{DB}?mode=ro",uri=True); target=sqlite3.connect(snapshot)
        with target:source.backup(target)
        target.close(); source.close()
        archive=os.path.join(BACKUP_DIR,f"keychain-{stamp}.tar.gz")
        with tarfile.open(archive,"w:gz") as tar:
            tar.add(snapshot,arcname="keychain.db")
            tar.add(DEVICE_KEY,arcname=".device-key")
        os.chmod(archive,0o600)
    finally:
        if os.path.exists(snapshot):os.unlink(snapshot)
    backups=sorted((os.path.join(BACKUP_DIR,x) for x in os.listdir(BACKUP_DIR) if x.startswith("keychain-") and x.endswith(".tar.gz")),key=os.path.getmtime,reverse=True)
    for old in backups[max(1,KEEP):]:os.unlink(old)
    print(archive)

if __name__=="__main__":main()
