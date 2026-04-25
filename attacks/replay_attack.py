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

from time import sleep

from ground_station import GroundStation, SecurityException


class ReplayAttacker:
    """
    Simulates an attacker who captures and replays valid packets.

    The attacker has no cryptographic keys — they simply store a copy of
    a packet that was already accepted by the GCS and submit it again.
    """

    def __init__(self):
        self.captured_packet: dict | None = None
        sleep(1)
        print("[Replay Attacker] Initialised.")

    def capture(self, packet: dict) -> None:
        """
        Record a copy of a valid packet intercepted from the channel.

        Parameters
        ----------
        packet : a packet dict that was previously accepted by the GCS
        """
        self.captured_packet = packet
        sleep(1)
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
        if self.captured_packet is None:
            print("[Replay Attacker] Nothing captured yet.")
            return
        sleep(1)
        print("[Replay Attacker] Re-submitting captured packet to Ground Station...")
        try:
            gcs.receive_message(self.captured_packet)
            print("[Replay Attacker] REPLAY SUCCEEDED - WE BROKE THE SYSTEM !!")
        except SecurityException as exc:
            sleep(1)
            print(f"\n[Ground Station] Replay attack BLOCKED: {exc}")
            print("SYSTEM SECURE.\n")
            sleep(1)
