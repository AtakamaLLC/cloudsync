# Misc dev notes

Put development notes here.

## Env Vars and Integration tests

When performing integration tests with cloud providers, credentials will be needed.

To encrypt env vars for this project, run:

    travis encrypt --pro "ENVVAR=VALUE" --add

These vars will *only* be available when the pull req is from within the main repo's "organization".  

External pull reqs that affect provider logic should be carefully manually verified to ensure 
that they don't leak test tokens, merged to a feature branch, and resubmitted by a member, 
otherwise integration tests will never run for that branch.

TODO: Maybe we can "smartly" allow tests to be skipped if provider code isn't 
touched in the pull req.
