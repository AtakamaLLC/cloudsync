### Misc dev notes

* Disconnect after token error

Currently it's critical to "disconnect" every time a CloudTokenError is raised.

There are some unit tests that check obvious cases and assert not connected.

Otherwise the event loop won't try to reauthenticate .... since "connected" currently implies "connected and authenitcated".

* Env Vars and Integration tests

When performing integration tests with cloud providers, credentials will be needed.

To encrypt env vars for this project, run:

    travis encrypt --pro "ENVVAR=VALUE" --add

These vars will *only* be available when the pull req is from within the main repo's "organization".  

External pull reqs that affect provider logic should be carefully manually verified to ensure 
that they don't leak test tokens, merged to a feature branch, and resubmitted by a member, 
otherwise integration tests will never run for that branch.
