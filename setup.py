from setuptools import setup  # pragma: no cover
import sys  # pragma: no cover

setup(  # pragma: no cover
    name='cloudsync',
    version='2.4.5a',
    packages=['cloudsync', 'cloudsync.sync', 'cloudsync.oauth', 'cloudsync.tests', 'cloudsync.tests.fixtures',
              'cloudsync.command', 'cloudsync.providers'],
    url='',
    license='',
    author='Atakama',
    author_email='',
    description=''
)

print("WARNING: setup.py is intended for test use only, not for production", file=sys.stderr)  # pragma: no cover
