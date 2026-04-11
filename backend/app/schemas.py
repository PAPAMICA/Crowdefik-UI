from pydantic import BaseModel, ConfigDict, Field


class TokenOut(BaseModel):
    access_token: str
    token_type: str = "bearer"


class LoginIn(BaseModel):
    username: str
    password: str


class UserOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    username: str
    is_superuser: bool


class UserCreateIn(BaseModel):
    username: str = Field(min_length=2, max_length=128)
    password: str = Field(min_length=8, max_length=256)
    is_superuser: bool = False


class RouterScopeIn(BaseModel):
    router_name: str = Field(min_length=1, max_length=512)


class InstanceSettingsOut(BaseModel):
    traefik_api_url: str
    traefik_basic_user: str | None
    crowdsec_lapi_url: str
    has_traefik_basic_password: bool
    has_crowdsec_api_key: bool
    has_abuseipdb_api_key: bool
    crowdsec_machine_id: str | None
    has_crowdsec_machine_password: bool
    crowdsec_container_name: str | None
    traefik_container_name: str | None


class InstanceSettingsUpdateIn(BaseModel):
    traefik_api_url: str | None = None
    traefik_basic_user: str | None = None
    traefik_basic_password: str | None = None
    crowdsec_lapi_url: str | None = None
    crowdsec_api_key: str | None = None
    abuseipdb_api_key: str | None = None
    crowdsec_machine_id: str | None = None
    crowdsec_machine_password: str | None = None
    crowdsec_container_name: str | None = None
    traefik_container_name: str | None = None


class CrowdsecToggleIn(BaseModel):
    enabled: bool
