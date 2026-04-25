"""
message.py
================
DroneMessage - the telemetry payload sent from the Drone to the GCS.

Coordinate system
-----------------
The Ground Control Station sits at the origin (0, 0, 0).
All positions are in metres relative to that origin.
Velocities are in m/s along each axis.

Replay protection
-----------------
Every message carries a UUID4 nonce generated at construction time.
The GCS's NonceManager checks this nonce is unseen before accepting the message.
Timestamps are intentionally omitted - nonce-based replay protection is used instead.
"""

import json
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Tuple


class DroneStatus(Enum):
    """
    Operational states the drone can report. In this implementation, it is treated as the most critical part of the Drone message. For 
    example, a tampered message showing "LANDING" instead of "FLYING" is assumed to have devastating affects, leading to complete mission
    and security failure.
    """
    FLYING = "FLYING"
    HOVERING = "HOVERING"
    LANDING = "LANDING"
    RETURNING = "RETURNING"

@dataclass
class DroneMessage:
    """
    Class defined for a complete packet from the Drone
    """ 
    drone_id: str #Identity of the drone
    position: Tuple[float, float, float]
    velocity: Tuple[float, float, float]
    battery_pct: float
    status: DroneStatus #Treated as the most critical value in the packet
    mission_id: str
    nonce: str = field(default_factory=lambda: str(uuid.uuid4())) #Randomly generate nonce to deal with replay attacks


    def to_json(self) -> str:
        """
        Serialise the message to a deterministic JSON string.
        """
        return json.dumps(
            {
                "drone_id":    self.drone_id,
                "position":    list(self.position),
                "velocity":    list(self.velocity),
                "battery_pct": self.battery_pct,
                "status":      self.status.value,
                "mission_id":  self.mission_id,
                "nonce":       self.nonce,
            },
            sort_keys=True,
        )

    @classmethod
    def from_json(cls, json_str: str) -> "DroneMessage":
        """
        Deserialise a DroneMessage from a JSON string.
        """
        data = json.loads(json_str)
        return cls(
            drone_id = data["drone_id"],
            position = tuple(data["position"]),
            velocity = tuple(data["velocity"]),
            battery_pct = data["battery_pct"],
            status = DroneStatus(data["status"]),
            mission_id = data["mission_id"],
            nonce = data["nonce"],
        )

    def printer(self) -> str:
        """
        Helper to print the entire Drone message in a standard format.
        """
        return (
            f"\n    id      : {self.drone_id} "
            f"\n    pos     : {self.position} "
            f"\n    vel     : {self.velocity}"
            f"\n    battery : {self.battery_pct:.1f}%"
            f"\n    status  : {self.status.value}"
            f"\n    mission : {self.mission_id})"
        )
