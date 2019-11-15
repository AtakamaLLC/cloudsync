#!/bin/bash

# upload to codecov
codecov --env TRAVIS_OS_NAME || ( sleep 5 && codecov --env TRAVIS_OS_NAME )
