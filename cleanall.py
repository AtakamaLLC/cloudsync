import threading

from cloudsync import *

from cloudsync.providers import GDriveProvider, DropboxProvider, BoxProvider, OneDriveProvider

gd = GDriveProvider.test_instance()
db = DropboxProvider.test_instance()
bx = BoxProvider.test_instance()
od = OneDriveProvider.test_instance()

threads = []

provs = [gd, db, bx, od]

for prov in provs:
    print(prov._test_creds)
    prov.connect(prov._test_creds)

    def run(prov):
        ld = list(prov.listdir_path("/"))
        print(prov.name, "# folder count:", len(ld))
        oid = prov.info_path("/").oid
        prov.rmtree(oid)
        print(prov.name, "# done")
    t = threading.Thread(target=lambda: run(prov), daemon=True)
    t.start()
    threads.append(t)

for t in threads:
    t.join()
