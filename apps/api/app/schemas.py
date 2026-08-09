from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator


class ORMModel(BaseModel):
    model_config = ConfigDict(from_attributes=True)


class RegisterRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=12, max_length=256)
    display_name: str = Field(min_length=1, max_length=160)
    organization_name: str = Field(min_length=1, max_length=160)
    organization_slug: str = Field(
        pattern=r"^[a-z0-9](?:[a-z0-9-]{0,78}[a-z0-9])?$"
    )

    @field_validator("password")
    @classmethod
    def password_complexity(cls, value: str) -> str:
        categories = [
            any(character.islower() for character in value),
            any(character.isupper() for character in value),
            any(character.isdigit() for character in value),
            any(not character.isalnum() for character in value),
        ]
        if sum(categories) < 3:
            raise ValueError(
                "Password must use at least three character categories."
            )
        return value


class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=1, max_length=256)


class CreateOrganizationRequest(BaseModel):
    name: str = Field(min_length=1, max_length=160)
    slug: str = Field(
        pattern=r"^[a-z0-9](?:[a-z0-9-]{0,78}[a-z0-9])?$"
    )


class CreateProjectRequest(BaseModel):
    name: str = Field(min_length=1, max_length=160)
    slug: str = Field(
        pattern=r"^[a-z0-9](?:[a-z0-9-]{0,78}[a-z0-9])?$"
    )
    description: str | None = Field(default=None, max_length=4000)


class UpdateMembershipRoleRequest(BaseModel):
    role: str = Field(
        pattern=(
            r"^(owner|administrator|developer|analyst|operator|viewer|"
            r"billing_manager)$"
        )
    )


class CreateApiKeyRequest(BaseModel):
    name: str = Field(min_length=1, max_length=160)
    scopes: list[str] = Field(min_length=1, max_length=30)
    expires_at: datetime | None = None
    environment: str = Field(default="live", pattern=r"^(live|test)$")


class UserSummary(BaseModel):
    id: UUID
    email: EmailStr
    display_name: str


class MembershipSummary(ORMModel):
    id: UUID
    organization_id: UUID
    role: str
    status: str
    version: int


class OrganizationSummary(ORMModel):
    id: UUID
    name: str
    slug: str
    status: str
    version: int


class ProjectSummary(ORMModel):
    id: UUID
    organization_id: UUID
    name: str
    slug: str
    description: str | None
    status: str
    max_active_leases: int
    version: int


class ApiKeySummary(ORMModel):
    id: UUID
    organization_id: UUID
    name: str
    public_prefix: str
    last_four: str
    scopes: list[str]
    environment: str
    created_at: datetime
    expires_at: datetime | None
    revoked_at: datetime | None


class SessionResponse(BaseModel):
    user: UserSummary
    memberships: list[MembershipSummary]
    organizations: list[OrganizationSummary]
    csrf_token: str


class CreatedApiKeyResponse(BaseModel):
    key: ApiKeySummary
    token: str
    warning: str = "This token is shown only once."
