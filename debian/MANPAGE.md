# Man Page Generation

Package manpage is written in Markdown and we can use pandoc to convert it into the correct format.

## Install Dependencies

no armhf package for pandoc, there is an arm64 host: 

```
cd ~
wget https://github.com/jgm/pandoc/releases/download/2.12/pandoc-2.12-1-arm64.deb
sudo apt install ~/pandoc-2.12-1-arm64.deb
```

## Generate Man Page

first time:

```
chmod +x manpage.sh
```

Run manpage.sh:

```
~/manpage.sh
```

## View Man Page

man ./wlanpi-profiler.1
