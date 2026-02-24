from kp2bw.bw_serve import sanitize_cli_output


def assert_redacts_known_secrets() -> None:
    raw = "unlock failed: password=super-secret token super-secret session abc123"
    sanitized = sanitize_cli_output(raw, secrets=("super-secret", "abc123"))
    if "super-secret" in sanitized or "abc123" in sanitized:
        raise AssertionError(f"secret leaked in sanitized output: {sanitized!r}")
    if sanitized.count("***") != 3:
        raise AssertionError(f"expected 3 redactions, got: {sanitized!r}")


def assert_normalizes_whitespace() -> None:
    raw = "line1\n\tline2   line3"
    sanitized = sanitize_cli_output(raw)
    expected = "line1 line2 line3"
    if sanitized != expected:
        raise AssertionError(f"expected {expected!r}, got {sanitized!r}")


def assert_truncates_long_output() -> None:
    raw = "x" * 30
    sanitized = sanitize_cli_output(raw, max_chars=10)
    expected = "xxxxxxxxxx...[truncated]"
    if sanitized != expected:
        raise AssertionError(f"expected {expected!r}, got {sanitized!r}")


def assert_redacts_before_truncation() -> None:
    raw = "token=abcdef " + ("z" * 300)
    sanitized = sanitize_cli_output(raw, secrets=("abcdef",), max_chars=20)
    if "abcdef" in sanitized:
        raise AssertionError(f"secret leaked in truncated output: {sanitized!r}")


def main() -> None:
    assert_redacts_known_secrets()
    assert_normalizes_whitespace()
    assert_truncates_long_output()
    assert_redacts_before_truncation()
    print("bw serve sanitization test passed")


if __name__ == "__main__":
    main()
