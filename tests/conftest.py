import os

import pytest

# Never let a test reach real AWS: dummy credentials, no config files.
for _k, _v in {
    "AWS_ACCESS_KEY_ID": "testing",
    "AWS_SECRET_ACCESS_KEY": "testing",
    "AWS_SESSION_TOKEN": "testing",
    "AWS_DEFAULT_REGION": "us-east-1",
    "AWS_CONFIG_FILE": os.devnull,
    "AWS_SHARED_CREDENTIALS_FILE": os.devnull,
}.items():
    os.environ[_k] = _v
os.environ.pop("AWS_PROFILE", None)


@pytest.fixture
def moto_env(monkeypatch):
    """Inside moto, the default AWS hostnames are intercepted; a custom endpoint would not be."""
    monkeypatch.delenv("AWS_ENDPOINT_URL", raising=False)
    from moto import mock_aws

    with mock_aws():
        yield
