<!-- 
[![Build Status](https://travis-ci.com/AtakamaLLC/cloudsync.svg?branch=master)](https://travis-ci.com/AtakamaLLC/cloudsync)
-->

## cloudsync README

Python Cloud Synchronization Library

    pip install cloudsync

Example:

    from cloudsync import CloudSync, CloudSyncProvider

    local = CloudSyncProvider("local", path="/usr/home/alice/test", monitor=True)

    remote = CloudSyncProvider("gdrive", path="/test-folder")

    remote.connect()

    sync = CloudSync(local, remote)

    sync.start()

    with open("/usr/home/alice/test/hello.txt", "w") as f:
        f.write("hello")

    # give the monitor a second to notice the change
    # alternatively we can "poke" the local provider, forcing a sync

    time.sleep(1)
    
    sync.wait(timeout=10)

    # using no_poke to deliberately trick our sync into *not* knowing about the rename 
    remote.rename("/test-folder/hello.txt", "/test-folder/goodbye.txt", no_poke=True)

    # we should still sync properly because of the event cursor
    while not os.path.exists("/usr/home/alice/test/goodbye.txt"):
        time.sleep(1)

