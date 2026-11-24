from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    # Filled in later steps - the app runs without them for now
    database_url: str | None = None
    gemini_api_key: str | None = None
    safe_browsing_key: str | None = None

    frontend_origin: str = "http://localhost:5173"
    max_message_chars: int = 2000


settings = Settings()
