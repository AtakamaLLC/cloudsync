[![Build Status](https://travis-ci.com/AtakamaLLC/cloudsync.svg?branch=master&token=WD7aozR2wQ3ePGe1QpA8)](https://travis-ci.com/AtakamaLLC/cloudsync)
[![Code Coverage](https://codecov.io/gh/AtakamaLLC/cloudsync/branch/master/graph/badge.svg)](https://codecov.io/gh/AtakamaLLC/cloudsync)


# cloudsync README

Python Cloud Synchronization Library

## Installation

```bash
pip install cloudsync

# install provider support
pip install cloudsync-gdrive
```

## Links

*   [Documentation](https://atakama-llc-cloudsync.readthedocs-hosted.com/en/latest/)
*   [Source Code + Issue Tracker](https://github.com/AtakamaLLC/cloudsync)

## Command-line Example

```bash

cloudsync sync --help

cloudsync sync file:c:/users/me/documents gdrive:/mydocs

# on linux you can pass -D for 'daemon mode', which will detatch and run in the background
```
## Example of a single cloud provider integration

```python
import cloudsync

# Get a generic client_id and client_secret. Do not use this in production code.
# For more information on getting your own client_id and client_secret, see README_OAUTH.md
oauth_config = cloudsync.command.utils.generic_oauth_config('gdrive')

# get an instance of the gdrive provider class
provider = cloudsync.create_provider('gdrive', oauth_config=oauth_config)

# Start the oauth process to login in to the cloud provider
creds = provider.authenticate()

# Use the credentials to connect to the cloud provider
provider.connect(creds)

# Perform cloud operations
for entry in provider.listdir_path("/"):
    print(entry.path)
```
## Example of a syncronization between two cloud providers

```python
import cloudsync
import tempfile
import time

# a little setup
local_root = tempfile.mkdtemp()
remote_root = "/cloudsync_test/" + time.strftime("%Y%m%d%H%M")
provider_name = 'gdrive'
print("syncronizing between %s locally and %s on %s" % (local_root, remote_root, provider_name))

# Get a generic client_id and client_secret. Do not use this in production code.
# For more information on getting your own client_id and client_secret, see README_OAUTH.md
cloud_oauth_config = cloudsync.command.utils.generic_oauth_config(provider_name)

# get instances of the local file provider and cloud provider from the provider factory
local = cloudsync.create_provider("filesystem")
remote = cloudsync.create_provider(provider_name, oauth_config=cloud_oauth_config)

# Authenticate with the remote provider using OAuth
creds = remote.authenticate()

# Connect with the credentials acquired by authenticating with the provider
local.namespace = local_root  # filesystem provider wants to know the root namespace before connecting
local.connect(None)
remote.connect(creds)

# Create the folder on google drive to syncronize locally
print("Creating folder %s on %s" % (remote_root, provider_name))
remote.mkdirs(remote_root)  # provider.mkdirs() will automatically create any necessary parent folders

# Specify which folders to syncronize
sync_roots = (local_root, remote_root)

# instantiate a new sync engine and start syncing
sync = cloudsync.CloudSync((local, remote), roots=sync_roots)
sync.start()

# should sync this file as soon as it's noticed by watchdog
local_hello_path = local.join(local_root, "hello.txt")
print("Creating local file %s" % local_hello_path)
with open(local_hello_path, "w") as f:
    f.write("hello")

# note remote.join, NOT os.path.join... Gets the path separator correct
remote_hello_path = remote.join(remote_root, "hello.txt")

# wait for sync to upload the new file to the cloud
while not remote.exists_path(remote_hello_path):
    time.sleep(1)

remote_hello_info = remote.info_path(remote_hello_path)

# rename in the cloud
local_goodbye_path = local.join(local_root, "goodbye.txt")
remote_goodbye_path = remote.join(remote_root, "goodbye.txt")
print("renaming %s to %s on %s" % (remote_hello_path, remote_goodbye_path, provider_name))
remote.rename(remote_hello_info.oid, remote_goodbye_path)  # rename refers to the file to rename by oid

# wait for sync to cause the file to get renamed locally
while not local.exists_path(local_goodbye_path):
    time.sleep(1)

print("synced")

sync.stop(forever=True)
local.disconnect()
remote.disconnect()
```
