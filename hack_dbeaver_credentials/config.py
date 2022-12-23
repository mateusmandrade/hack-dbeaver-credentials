from prettyconf import config


class Settings:
    DBEAVER_CREDENTIALS_KEY = config("DBEAVER_CREDENTIALS_KEY")


settings = Settings()
