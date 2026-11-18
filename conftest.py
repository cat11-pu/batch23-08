import pytest
@pytest.fixture(autouse=True)
def clean_temp():
    yield
