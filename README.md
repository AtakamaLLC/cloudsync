<!-- 
[![Build Status](https://travis-ci.com/AtakamaLLC/cloudsync.svg?branch=master)](https://travis-ci.com/AtakamaLLC/cloudsync)
-->

## cloudsync README

Python Cloud Synchronization Library

    pip install cloudsync

Contrived Example:

    import cloudsync

    # local file provide + gdrive provider
    local = cloudsync.get_provider("file")
    remote = cloudsync.get_provider("gdrive")

    # oauth
    creds = remote.authorize()

    # connect with creds
    remote.connect(creds)

    # root for sync
    roots = ("/home/me/gd", "/")

    # new sync engine
    sync = cloudsync.CloudSync((local, remote), roots)

    sync.start()

    # should sync this file as soon as it's noticed by watchdog
    with open("/home/me/gd/hello.txt", "w") as f:
        f.write("hello")

    # wait for sync
    while not remote.exists_path("/home/alice/hello.txt"):
        time.sleep(1)

    # rename in the cloud
    remote.rename("/hello.txt", "/goodbye.txt")

    # wait for sync
    while not local.exists_path("/home/alice/goodbye.txt"):
        time.sleep(1)

    print("synced")
