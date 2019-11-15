from cloudsync import *

from cloudsync.tests.providers.gdrive import gdrive_provider
from cloudsync.tests.providers.dropbox import dropbox_provider

gd = gdrive_provider()
gd.name = "gdrive"

db = dropbox_provider()
db.name = "dropbox"


def _rmtree(prov, oid, path):
    count = 0
    try:
        for e in prov.listdir(oid):
            e.path = prov.join(path, e.name)
            if e.otype is FILE:
                print(prov.name, "del", e.path)
                prov.delete(e.oid)
                count += 1
            else:
                print(prov.name, "into", e.oid, e.path)
                count += _rmtree(prov, e.oid, e.path)
                print(prov.name, "rmdir", e.path)
                prov.delete(e.oid)
                count += 1
    except CloudFileNotFoundError:
        pass
    return count


threads = []

for prov in (gd, db):
    prov.connect(prov.creds)
    def run(prov):
        print(prov.name, "start")
        oid = prov.info_path("/").oid
        count = _rmtree(prov, oid, "/")
        print(prov.name, "done", count)
    t = threading.Thread(target=lambda: run(prov), daemon=True)
    t.start()
    threads.append(t)

for t in threads:
    t.join()
