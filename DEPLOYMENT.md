# Releases

wlanpi-profiler releases are handled through Github workflows and leverage `https://apt.fury.io/dfinimundi/Packages` until we find a new home.

There are two workflows defined.

1. When a pull request on `<repo>/debian/changelog` is made, the workflow will build the debian package, create an artifact, and upload to GitHub. This workflow does not upload to repository. It is located at `<repo>/.github/workflows/build-debian-package.yml`. The purpose of this action is potentially to review and validate artifacts before uploading to production.

2. When a push to `<repo>/debian/changelog` is made, the workflow will build the debian package, create an artifact, upload artifact to Github, and finaly upload the package to the repository.

## Workflow Process

### debian packaging

On your build host, install the build tools (these are only needed on the device doing the build):

```bash
sudo apt-get install build-essential debhelper devscripts equivs python3-pip python3-all python3-dev python3-setuptools dh-virtualenv
```

Install Python depends so that the tooling doesn't fail when it tries to evaluate which tests to run.

```bash
python3 -m pip install mock
```

You are ready to build. From the root directory of this repository run the following command:

```bash
debuild
```

or if you don''t want to satisfy build depends:

```bash
dpkg-buildpackage -us -uc -b
```

Use `dpkg -i <file.deb>` to install and test the generated package.

### debchange - tool for maintaining the source package changelog file

It is recommended to use `debchange` or its alias `dch` to assist in the modification of the changelog. You should 

If you are using debchange, it is a good idea to set environment variables on your development machine. If you do not, when `debchange` is invoked, it will automatically author the change with `<user@systemname>` when you should use the `Dale Cooper <special_agent@twinpeaks.com>` format. 

### debchange - usage

#### Create a new version entry

You can run debchange from the root of the repository as debchange will climb the directory tree until it finds a `debian/changelog` file.

```
(venv) wlanpi@rbpi4b-8gb:[~/dev/profiler]: debchange
```

#### Update an existing version entry

You should minially use `dch -i` when adding a new changelog because `-i` increases the release number and adds a changelog entry.

If you want to edit the changelog without changing the version or adding a new entry, use `-e` instead of `-i`.

### debchange - versions

On version numbers, from the Debian maintainers guide:

> One tricky case can occur when you make a local package, to experiment with the packaging before uploading the normal version to the official archive, e.g., 1.0.1-1. For smoother upgrades, it is a good idea to create a changelog entry with a version string such as 1.0.1-1~rc1. You may unclutter changelog by consolidating such local change entries into a single entry for the official package.

### debchange - environment variables

You will likely want to set the `DEBFULLNAME` and `DEBEMAIL` environment variables on your development system. Two options demonstrated:

Set per session:

```bash
(venv) wlanpi@rbpi4b-8gb:[~/dev/profiler]: export DEBFULLNAME="Josh Schmelzle"
(venv) wlanpi@rbpi4b-8gb:[~/dev/profiler]: export DEBEMAIL="Josh Schmelzle <josh@joshschmelzle.com>"
```

Set to take effect at shell login via `~/.profile`


```bash
# vim ~/.profile
# append the following:
export DEBFULLNAME="Josh Schmelzle"
export DEBEMAIL="Josh Schmelzle <josh@joshschmelzle.com>"
```

### debchange - review

For more information on debchange review the manpages by running `man debchange` from your terminal.

Additionally review the [Debian maintainers guide Chapter 8](https://www.debian.org/doc/manuals/maint-guide/update.en.html).


## APPENDIX

### Debian Packaging Breakdown

#### changelog

Contains changelog information and sets the version of the package

#### control

provides dependencies, package name, and other package meta data.

#### compat

sets compatibility level for debhelper

#### rules

this is the build recipe for make

#### wlanpi-profiler.install

this handles placing our config file in /etc

#### wlanpi-profiler.links

handles symlinks

#### wlanpi-profiler.postinst.debhelper

`dh-virtualenv` has an autoscript which handles this for us.

#### wlanpi-profiler.postrm.debhelper

`dh-virtualenv` has an autoscript which handles this for us.
#### wlanpi-profiler.service

`dh` automatically picks up and installs this systemd service

#### wlanpi-profiler.triggers

tells dpkg what packages we're interested in

### Installing dh-virtualenv

Some OS repositories have packages already. 

```
sudo apt install dh-virtualenv
```

If not available, you can build it from source:

```
cd ~

# Install needed packages
sudo apt-get install devscripts python3-virtualenv python3-sphinx \
                     python3-sphinx-rtd-theme git equivs
# Clone git repository
git clone https://github.com/spotify/dh-virtualenv.git
# Change into working directory
cd dh-virtualenv
# This will install build dependencies
sudo mk-build-deps -ri
# Build the *dh-virtualenv* package
dpkg-buildpackage -us -uc -b

# And finally, install it (you might have to solve some
# dependencies when doing this)
sudo dpkg -i ../dh-virtualenv_<version>.deb
```