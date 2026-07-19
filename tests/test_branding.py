from __future__ import annotations

from pathlib import Path

from system_info.assets import FLAGS_DIRECTORY, load_flag_image
from system_info.product import DATABASE_FILENAME, PRODUCT_NAME


def test_vigilscope_product_metadata_and_flag_assets() -> None:
    assert PRODUCT_NAME == "VigilScope"
    assert DATABASE_FILENAME == "vigilscope.db"
    assert (FLAGS_DIRECTORY / "tr.png").read_bytes().startswith(b"\x89PNG")
    assert (FLAGS_DIRECTORY / "gb.png").read_bytes().startswith(b"\x89PNG")


def test_flag_loader_has_text_fallback() -> None:
    def fail(**_kwargs):
        raise OSError("missing")

    image, text = load_flag_image("tr", loader=fail)
    assert image is None
    assert text == "TR"


def test_repository_facing_documents_use_vigilscope_name() -> None:
    root = Path(__file__).resolve().parent.parent
    assert "# VigilScope" in (root / "README.md").read_text(encoding="utf-8")
    for path in (
        root / "README.md",
        root / "CONTRIBUTING.md",
        root / "SECURITY.md",
        root / "docs" / "screenshots" / "README.md",
    ):
        text = path.read_text(encoding="utf-8")
        assert "ProjectOne" not in text

