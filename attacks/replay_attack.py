"""
attacks/replay_attack.py
========================
Replay Attack Simulation

What is a replay attack?
-------------------------
An attacker captures a legitimately sent and accepted packet, then
re-sends that same packet later to the GCS — hoping the GCS will
process it as a fresh, valid command.

This is dangerous in drone systems because:
  - A captured "land" or "return home" command could be replayed at any time.
  - A legitimate telemetry packet could be used to confuse the operator.

How our system prevents it
---------------------------
Every DroneMessage contains a UUID4 nonce generated at creation time.
When the GCS first accepts a packet it records the nonce.
Any subsequent packet bearing the same nonce is immediately rejected
by the NonceManager — the GCS never processes it.

Simulation
----------
ReplayAttacker
    capture(packet)   : records a copy of a valid packet
    attack(gcs)       : replays the captured packet at the GCS
"""

import copy

from ground_station import GroundStation, SecurityException


class ReplayAttacker:
    """
    Simulates an attacker who captures and replays valid packets.

    The attacker has no cryptographic keys — they simply store a copy of
    a packet that was already accepted by the GCS and submit it again.
    """

    def __init__(self):
        self._captured_packet: dict | None = None
        print("[Replay Attacker] Initialised.")

    def capture(self, packet: dict) -> None:
        """
        Record a copy of a valid packet intercepted from the channel.

        Parameters
        ----------
        packet : a packet dict that was previously accepted by the GCS
        """
        self._captured_packet = copy.deepcopy(packet)
        print("[Replay Attacker] Packet captured from the channel.")

    def attack(self, gcs: GroundStation) -> None:
        """
        Attempt to replay the captured packet to the GCS.

        Expected outcome: SecurityException is raised by the GCS's
        NonceManager because the nonce was already registered.

        Parameters
        ----------
        gcs : the target GroundStation instance
        """
        if self._captured_packet is None:
            print("[Replay Attacker] Nothing captured yet.")
            return

        print("[Replay Attacker] Re-submitting captured packet to GCS...")
        try:
            gcs.receive_telemetry(self._captured_packet)
            # Should never reach here
            print("[Replay Attacker] !! Replay SUCCEEDED — SYSTEM IS VULNERABLE !!")
        except SecurityException as exc:
            print(f"[GCS] ✗ Replay attack BLOCKED: {exc}")
