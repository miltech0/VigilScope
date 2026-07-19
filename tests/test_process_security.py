import pytest

from system_info.process_security import mask_sensitive_command_line


@pytest.mark.parametrize(
    ("source", "expected"),
    [
        ("app.exe --password gizli123 --port 80", "app.exe --password *** --port 80"),
        ("app --token=abc123", "app --token=***"),
        ("app --api-key secret", "app --api-key ***"),
        ("password=hunter2 mode=test", "password=*** mode=test"),
        ("token='çok gizli' next=1", "token=*** next=1"),
        ("api_key=xyz", "api_key=***"),
        ("Authorization: Bearer eyJhbGciOi", "Authorization: Bearer ***"),
    ],
)
def test_sensitive_command_line_values_are_masked(source, expected) -> None:
    assert mask_sensitive_command_line(source) == expected


def test_normal_command_line_is_not_changed() -> None:
    command = "python app.py --port 8080 --verbose"
    assert mask_sensitive_command_line(command) == command

