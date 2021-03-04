# Contribution Guidelines

To get the greatest chance of helpful responses, please observe the
following additional notes.

## Questions

The GitHub issue tracker is for *bug reports* and *feature requests*. Please do
not use it to ask questions about usage. These questions should
instead be directed through other channels.

## Good Bug Reports

Please be aware of the following things when filing bug reports:

1. Avoid raising duplicate issues. *Please* use the GitHub issue search feature
   to check whether your bug report or feature request has been mentioned in
   the past. Duplicate bug reports and feature requests are a huge maintenance
   burden on the project maintainers. If it is clear from your report that you 
   would have struggled to find the original, that's ok, but if searching for 
   a selection of words in your issue title would have found the duplicate
   then the issue will likely be closed.

2. When filing bug reports about exceptions or tracebacks, please include the
   *complete* traceback. Partial tracebacks, or just the exception text, are
   not helpful. Issues that do not contain complete tracebacks may be closed
   without warning.

3. Make sure you provide a suitable amount of information to work with. This
   means you should provide:

   - Guidance on **how to reproduce the issue**. Ideally, this should be a
     *small* code sample that can be run immediately by the maintainers.
     Failing that, let us know what you're doing, how often it happens, what
     environment you're using, etc. Be thorough: it prevents us needing to ask
     further questions.
   - Tell us **what you expected to happen**. When we run your example code,
     what are we expecting to happen? What does "success" look like for your
     code?
   - Tell us **what actually happens**. It's not helpful for you to say "it
     doesn't work" or "it fails". Tell us *how* it fails: do you get an
     exception? How was the actual result different from your expected result?
   - Tell us **what version you're using**, and
     **how you installed it**. Different versions behave
     differently and have different bugs.
   
   If you do not provide all of these things, it can take us much longer to
   fix your problem. If we ask you to clarify these and you never respond, we
   will close your issue without fixing it.

## Code Contributions

### Development Setup  ('without pip install or pipx', 'may be recommended for development work'):

```
git clone <repo>
cd <repo>
virtualenv venv
source venv/bin/activate
pip install -r requirements.txt
sudo python3 -m profiler2 
sudo python3 -m profiler2 <optional params>
sudo python3 -m profiler2 -c 44 -s "dev" -i wlan2 --no11r --logging debug
```

- note that package name is `profiler2` while the console_scripts entry point is `profiler`.

### Before You Start

To increase the chances of PR approval, first, talk to one of the core team members. Aligning your ideas with the project team will save everybody's time. 

### Pull Requests

Before submitting a PR perform the following:

1. Lint your code with `tox -e lint` and make sure it passes.

1. Format your code with `tox -e format` (this basically just runs black for now).

2. Create a test that validates your changes. this test should go in `/tests`.

3. Ensure your tests pass by running `tox`.

Failure to do so means it will take longer to test, validate, and merge your PR into the repo.
