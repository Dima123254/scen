# -*- coding: utf-8 -*-
"""Pydantic-модели входных данных организации."""

from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class ZoneEnum(str, Enum):
    """Допустимые зоны размещения актива."""

    INTERNAL = "Internal"
    EXTERNAL = "External"
    DMZ = "DMZ"
    FILIAL = "Filial"


class AttackerLevelEnum(str, Enum):
    """Уровни возможностей нарушителя по методике."""

    N1 = "Н1"
    N2 = "Н2"
    N3 = "Н3"
    N4 = "Н4"


class Meta(BaseModel):
    """Метаданные описания."""

    model_config = ConfigDict(extra="ignore")

    company_name: str = Field(..., min_length=1, description="Наименование организации")
    system_name: str = Field(default="", description="Имя ИС или контура")
    author: str = Field(default="", description="Автор модели")
    date: str = Field(default="", description="Дата в произвольном формате")


class Asset(BaseModel):
    """Актив (объект воздействия)."""

    model_config = ConfigDict(extra="ignore")

    id: str = Field(..., min_length=1)
    name: str = Field(..., min_length=1)
    zone: ZoneEnum
    interfaces: list[str] = Field(default_factory=list)
    data_types: list[str] = Field(default_factory=list)
    description: str = ""


class TopologyLink(BaseModel):
    """Связь между активами (топология)."""

    model_config = ConfigDict(extra="ignore", populate_by_name=True)

    from_: str = Field(..., alias="from")
    to: str
    protocol: str = ""


class Attacker(BaseModel):
    """Модель нарушителя (из входного JSON)."""

    model_config = ConfigDict(extra="ignore")

    type: str = Field(..., min_length=1)
    level: AttackerLevelEnum
    category: str = Field(..., description="External или Internal")
    goals: list[str] = Field(default_factory=list)
    interfaces: list[str] = Field(
        default_factory=list,
        description="Доступные интерфейсы; пусто — берутся defaults из validation_config",
    )

    @field_validator("level", mode="before")
    @classmethod
    def validate_level(cls, v: Any) -> Any:
        if isinstance(v, str) and v not in {x.value for x in AttackerLevelEnum}:
            raise ValueError(
                f"level must be one of {[x.value for x in AttackerLevelEnum]}, got {v!r}"
            )
        return v

    @field_validator("category")
    @classmethod
    def normalize_category(cls, v: str) -> str:
        allowed = {"External", "Internal", "External/Internal"}
        if v not in allowed:
            raise ValueError(f"category must be one of {sorted(allowed)}, got {v!r}")
        return v


class BusinessProcess(BaseModel):
    """Бизнес-процесс и связанные угрозы."""

    model_config = ConfigDict(extra="ignore")

    name: str
    threats: list[str] = Field(default_factory=list)
    consequences: list[str] = Field(default_factory=list)


class CompanyData(BaseModel):
    """Корневая модель файла company_data.json."""

    model_config = ConfigDict(extra="ignore")

    meta: Meta
    assets: list[Asset] = Field(default_factory=list)
    topology: list[TopologyLink] = Field(default_factory=list)
    attackers: list[Attacker] = Field(default_factory=list)
    threats: list[str] = Field(default_factory=list, description="Список кодов УБИ")
    business_processes: list[BusinessProcess] = Field(default_factory=list)

    @model_validator(mode="after")
    def check_topology_asset_refs(self) -> CompanyData:
        """Проверка, что from/to топологии ссылаются на существующие активы."""
        ids = {a.id for a in self.assets}
        for link in self.topology:
            if link.from_ not in ids:
                raise ValueError(f"topology.from references unknown asset id: {link.from_!r}")
            if link.to not in ids:
                raise ValueError(f"topology.to references unknown asset id: {link.to!r}")
        return self
