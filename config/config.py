from dynaconf import Dynaconf

settings = Dynaconf(
    envvar_prefix="BE",
    settings_files=['config.yaml'],
)