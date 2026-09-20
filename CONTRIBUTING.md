# Contribution guidelines

Please review the WLAN Pi [contribution guidelines and policies](https://github.com/WLAN-Pi/.github/blob/main/docs/contributing.md).

### Development setup  ('without pip install or pipx', 'may be recommended for development work'):

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
sudo ./venv/bin/python3 -m profiler -c 44 -s "dev" -i wlan2 --no11r --debug --expert
```

### Branching model

`main` is the only long-lived branch in this repository, and it is both the
default branch and the release branch. All work happens on short-lived branches
created from `main` and merged back into `main` via a pull request.

Branch names follow the WLAN Pi conventions:

```
feature/<description>       # new features
bugfix/<description>        # bug fixes
hotfix/<description>        # urgent fixes against main
u/<username>/<description>  # personal work
```

This repository does **not** use a long-lived `dev`/`development` branch. Open
pull requests against `main`, not a `dev` branch. CI runs on pull requests and
on `main`, and releases are tagged on `main`.

### Before you start

Create an issue before you start on Pull Request (PR). Aligning your ideas with the project team will save everybody's time. 

### Pull requests

Open pull requests against `main`. Before submitting a PR perform the following:

1. Lint your code with `tox -e lint` and make sure it minimally passes the checks.
1. Format your code with `tox -e format` (this will run auto formatting tools)
1. Create a test that validates your changes. this test should go in `/tests`.
1. Ensure your tests pass by running `tox`.

Failure to do this means it will take longer to test, validate, and merge your PR into the repo.
