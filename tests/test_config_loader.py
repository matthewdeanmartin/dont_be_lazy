import pytest

from dont_be_lazy.config_loader import discover_config, load_toml


def test_load_toml_invalid_path(tmp_path):
    # load_toml expects the path to exist as checked by discover_config
    # but we can test it handles the case where it's called with something that fails open
    with pytest.raises(FileNotFoundError):
        load_toml(str(tmp_path / "missing.toml"))


def test_load_toml_valid(tmp_path):
    path = tmp_path / "test.toml"
    path.write_bytes(b"[tool.dont_be_lazy]\nfoo = 'bar'\n")
    data = load_toml(str(path))
    assert data == {"tool": {"dont_be_lazy": {"foo": "bar"}}}


def test_discover_config_explicit(tmp_path):
    path = tmp_path / "custom.toml"
    path.write_bytes(b"[tool.dont_be_lazy]\nfoo = 'bar'\n")
    # If explicit path has tool.dont_be_lazy, it returns that section
    assert discover_config(str(tmp_path), explicit=str(path)) == {"foo": "bar"}


def test_discover_config_explicit_raw(tmp_path):
    path = tmp_path / "custom.toml"
    path.write_bytes(b"foo = 'bar'\n")
    # If explicit path doesn't have tool.dont_be_lazy, it returns the whole dict
    assert discover_config(str(tmp_path), explicit=str(path)) == {"foo": "bar"}


def test_discover_config_pyproject(tmp_path):
    path = tmp_path / "pyproject.toml"
    path.write_bytes(b"[tool.dont_be_lazy]\nfoo = 'bar'\n")
    assert discover_config(str(tmp_path)) == {"foo": "bar"}


def test_discover_config_dont_be_lazy_toml(tmp_path):
    path = tmp_path / "dont_be_lazy.toml"
    path.write_bytes(b"foo = 'bar'\n")
    assert discover_config(str(tmp_path)) == {"foo": "bar"}


def test_discover_config_hidden_toml(tmp_path):
    path = tmp_path / ".dont-be-lazy.toml"
    path.write_bytes(b"foo = 'bar'\n")
    assert discover_config(str(tmp_path)) == {"foo": "bar"}


def test_discover_config_none(tmp_path):
    assert discover_config(str(tmp_path)) == {}


def test_discover_config_pyproject_no_section(tmp_path):
    path = tmp_path / "pyproject.toml"
    path.write_bytes(b"[tool.other]\nfoo = 'bar'\n")
    assert discover_config(str(tmp_path)) == {}
