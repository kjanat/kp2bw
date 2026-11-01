from snapshot import norm_login


def check_empty_password_matches_null() -> None:
    assert norm_login({"password": ""})["password"] is None
    assert norm_login({"password": None})["password"] is None
    assert norm_login({})["password"] is None


def check_password_kept() -> None:
    assert norm_login({"password": "hunter2"})["password"] == "hunter2"
    assert norm_login({"password": " "})["password"] == " "


def main() -> None:
    check_empty_password_matches_null()
    check_password_kept()
    print("snapshot normalization passed")


if __name__ == "__main__":
    main()
