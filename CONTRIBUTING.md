# Contribution Guidelines

Please review the WLAN Pi [contribution guidelines and policies](https://github.com/WLAN-Pi/.github/blob/main/docs/contributing.md).

### Development Setup  ('without pip install or pipx', 'may be recommended for development work'):

```
cd <where your dev folder is>
git clone <repo>
cd <repo>
virtualenv venv
source venv/bin/activate
pip install -U pip pip-tools setuptools wheel
pip install -r requirements.txt
sudo ./venv/bin/python3 -m profiler 
sudo ./venv/bin/python3 -m profiler <optional params>
sudo ./venv/bin/python3 -m profiler -c 44 -s "dev" -i wlan2 --no11r --logging debug
```

### Before You Start

Create an issue and get it approved before you start on Pull Request (PR). Aligning your ideas with the project team will save everybody's time. 

### Pull Requests

Before submitting a PR perform the following:

1. Lint your code with `tox -e lint` and make sure it minimally passes the checks.

1. Format your code with `tox -e format` (this will run autoflake with desired options, black, and isort on the profiler codebase)

2. Create a test that validates your changes. this test should go in `/tests`.

3. Ensure your tests pass by running `tox`.

Failure to do this means it will take longer to test, validate, and merge your PR into the repo.
