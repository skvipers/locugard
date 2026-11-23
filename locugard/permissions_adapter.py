"""Интерфейс диспетчера подтверждений (Permissions) для LocuGard.

Позволяет использовать встроенный `LocalPermissions` либо подключить собственный
диспетчер опасных действий хост-приложения с тем же контрактом
(`Action`, `Level`, `Risk`, `Outcome`, `submit`, `confirm`, `reject`).
"""
from __future__ import annotations

import secrets
import time
from dataclasses import dataclass, field
from enum import IntEnum
from pathlib import Path
from typing import Callable


class Level(IntEnum):
    FREE = 0
    REPORT = 1
    ASK = 2


class Risk(IntEnum):
    TRIVIAL = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3


@dataclass
class Action:
    name: str
    level: Level
    description: str
    run: Callable[[], str]
    external: bool = False
    terse: bool = False
    risk: Risk | None = None
    fingerprint: str | None = None
    created: float = field(default_factory=time.time)


@dataclass
class Outcome:
    status: str  # done | reported | pending | failed
    text: str
    pending_id: int | None = None


class LocalPermissions:
    """Минимальный автономный диспетчер подтверждений опасных действий с единым контрактом Permissions."""

    PENDING_TTL_S = 24 * 3600

    def __init__(self, data_dir: Path):
        self.data_dir = Path(data_dir)
        self.pending: dict[int, Action] = {}

    def submit(self, action: Action) -> Outcome:
        if action.level != Level.ASK:
            res = action.run()
            return Outcome("reported" if action.level == Level.REPORT else "done", res)
        pid = (1 << 64) + secrets.randbits(64)
        while pid in self.pending:
            pid = (1 << 64) + secrets.randbits(64)
        self.pending[pid] = action
        return Outcome("pending", f"Нужно подтверждение [{pid}]: {action.description}", pid)

    def confirm(self, pid: int, always: bool = False) -> Outcome:
        action = self.pending.pop(pid, None)
        if action is None or (time.time() - action.created > self.PENDING_TTL_S):
            return Outcome("failed", f"Запроса [{pid}] нет или он устарел.")
        try:
            res = action.run()
            return Outcome("reported", f"Сделано: {action.description}\n{res}")
        except Exception as e:
            return Outcome("failed", f"Не получилось: {type(e).__name__}: {e}")

    def reject(self, pid: int) -> Outcome:
        action = self.pending.pop(pid, None)
        if action is None:
            return Outcome("failed", f"Запроса [{pid}] нет или он устарел.")
        return Outcome("done", f"Отменено: {action.description}")
