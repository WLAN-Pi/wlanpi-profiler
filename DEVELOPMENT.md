# Initial Development Setup

## Repository

1. Clone repo to development host

2. Create and activate virtualenv

```bash
python3 -m venv venv
source venv/bin/activate
```

3. Update and install tools 

```bash
pip install -u pip pip-tools setuptools wheel
```

4. Install depends

```bash
pip install -r requirements.txt
```

## Building and Packaging

Refer to DEPLOYMENT.md
