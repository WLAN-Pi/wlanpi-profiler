Style Guide
===========

Adding Capabilities
-------------------

`CAPABILITY_LOGIC.md` should be updated whenever additional capabilities are added. 

Python conventions
------------------

- class names should use `UpperCamelCase`
- constant names should be `CAPITALIZED_WITH_UNDERSCORES`
- other names should use `lowercase_separated_by_underscores`
- private variables/methods should start with an undescore: `_myvar`
- some special class methods are surrounded by two underscores: `__init__`

CamelCase
---------

When using abbreviations with `CamelCase`, capitalize all the letters of the abbreviation. For example, `Dot11FT` is better than `Dot11Ft`.

Tox for testing and linting
---------------------------

Install tox:

```
$ python3 -m pip install tox 
```

You can now invoke tox in the directory where tox.ini resides.

These are some things you should before submitting a PR:

To initiate testing:

```
tox
```

We should lint our code. Example:

```
tox -e lint
```

We should format our code. Example:

```
tox -e format
```
