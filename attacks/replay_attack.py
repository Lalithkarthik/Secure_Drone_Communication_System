"""
attacks/replay_attack.py

This file handles the simulation of the replay attack. An attacker captures a legitimately sent and accepted packet, then re-sends that 
same packet later to the Ground Station, hoping that it is processed as a fresh and valid packet. In our implementation we considered the
most critical information to the "DroneStatus" (implemented as a class in tools/message.py). Any modification in this message is treated
as extremely dangerous.
1. A captured "land" or "return home" command could be replayed at any time.
2. A legitimate telemetry packet could be used to confuse the operator.
Our implementation uses unique Nonce within each session facilitated by the use of a NonceManager to prevent such attacks.
"""

from time import sleep

from ground_station import GroundStation, SecurityException

class ReplayAttacker:
    """
    Simulates an attacker who captures and replays valid packets. The attacker has no cryptographic keys - they simply store a copy of
    a packet that was already accepted by the gs and submit it again. In our implementation we hardcoded this caught packet as the first
    transmitted packet.
    """

    def __init__(self):
        self.captured_packet: dict | None = None
        sleep(1)
        print("[Replay Attacker] Initialised.")

    def capture(self, packet: dict) -> None:
        """
        Records a copy of a valid packet intercepted from the medium. In our case it is the first transmitted packet from the Drone to
        the Ground Station.
        """
        self.captured_packet = packet
        sleep(1)
        print("[Replay Attacker] Packet captured from the channel.")

    def attack(self, gs: GroundStation) -> None:
        """
        Attempt to replay the captured packet to the Ground Station. 
        """
        if self.captured_packet is None:
            print("[Replay Attacker] Nothing captured yet.")
            return
        sleep(1)
        print("[Replay Attacker] Re-submitting captured packet to Ground Station...")
        try:
            gs.receive_message(self.captured_packet)
            print("[Replay Attacker] REPLAY SUCCEEDED - WE BROKE THE SYSTEM !!")
        except SecurityException as exc:
            sleep(1)
            print(f"\n[Ground Station] Replay attack BLOCKED: {exc}")
            print("SYSTEM SECURE.\n")
            sleep(1)
