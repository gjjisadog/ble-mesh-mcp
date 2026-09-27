"""Explicit milestones for one Xiaomi Mesh registration transaction."""

from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum


class RegistrationStage(IntEnum):
    IDLE = 0
    CLOUD_AUTH_RESPONSE_RECEIVED = 1
    DEVICE_SIGNATURE_RECEIVED = 2
    CLOUD_BOUND = 3
    CONFIG_SENT = 4
    DEVICE_REGISTERED = 5  # Device returned 0x41.
    CLOUD_COMMITTED = 6  # provision_done completed successfully.


@dataclass(frozen=True)
class RegistrationProgress:
    stage: RegistrationStage = RegistrationStage.IDLE

    def advance(self, next_stage: RegistrationStage) -> "RegistrationProgress":
        next_stage = RegistrationStage(next_stage)
        if next_stage.value != self.stage.value + 1:
            raise ValueError(
                f"invalid registration transition: {self.stage.name} -> {next_stage.name}"
            )
        return RegistrationProgress(next_stage)
