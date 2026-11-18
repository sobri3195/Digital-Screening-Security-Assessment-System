from enum import StrEnum
from dataclasses import dataclass, field
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, model_validator
from typing_extensions import Annotated


class Platform(StrEnum):
    WINDOWS = "windows"
    ANDROID = "android"
    IOS = "ios"
    USB = "usb"
    OTHER = "other"


class Module(StrEnum):
    WINDOWS = "windows"
    SOFTWARE = "software"
    ANDROID = "android"
    IOS = "ios"
    FILES = "files"
    APK = "apk"
    MALWARE = "malware"
    VULNERABILITY = "vulnerability"
    INTELLIGENCE = "intelligence"


PLATFORM_MODULES = {
    Platform.WINDOWS: {Module.WINDOWS, Module.SOFTWARE, Module.VULNERABILITY},
    Platform.ANDROID: {Module.ANDROID, Module.APK},
    Platform.IOS: {Module.IOS},
    Platform.USB: set(),
    Platform.OTHER: set(),
}
COMMON_MODULES = {Module.FILES, Module.MALWARE, Module.INTELLIGENCE}
FILE_MODULES = {Module.FILES, Module.APK, Module.MALWARE}

Code = Annotated[
    str, StringConstraints(strip_whitespace=True, min_length=2, max_length=80, pattern=r"^[a-zA-Z0-9_.:/-]+$")
]
Label = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=160)]
Note = Annotated[str, StringConstraints(strip_whitespace=True, max_length=1000)]


class Input(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class Asset(Input):
    code: Code
    name: Label
    platform: Platform
    unit: Label


class Authorization(Input):
    asset_id: Code
    operator_code: Code
    reference: Code
    scope: Note = Field(min_length=8)
    authorized: Literal[True]
    modules: list[Module] = Field(min_length=1, max_length=9)
    local_host_confirmed: bool = False
    mode: Literal["quick", "comprehensive", "custom"] = "custom"

    @model_validator(mode="after")
    def unique_modules(self):
        if len(self.modules) != len(set(self.modules)):
            raise ValueError("Modul harus unik.")
        return self


class MobileCheck(Input):
    control: Code
    state: Literal["pass", "fail", "unknown", "not_applicable"]
    note: Note = ""


class Product(Input):
    vendor: Label
    name: Label
    version: Label


@dataclass(frozen=True)
class Finding:
    category: str
    title: str
    severity: str
    recommendation: str


@dataclass(frozen=True)
class Observation:
    source: str
    payload: dict
    findings: tuple[Finding, ...] = field(default_factory=tuple)
