from pathlib import Path

from models.settings import Settings

settings_file_path = Path(".config.json")


def get_settings() -> Settings:
    """
    Reads and returns the stored settings (if present).

    Returns:
        Settings: Stored or default settings.
    """
    settings = Settings()
    if settings_file_path.is_file():
        try:
            settings = Settings.parse_file(settings_file_path)
        except:
            pass  # some error happened reading the file, use defaults
    return settings


def save_settings(settings: Settings) -> None:
    """
    Stores changed settings.

    Args:
        settings (Settings): Settings to save.
    """
    settings_file_path.write_text(settings.json())
