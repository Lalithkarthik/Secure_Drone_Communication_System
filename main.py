"""
main.py
=======
Secure Drone Communication System — Demo Entry Point

Run with:   python main.py

Sequence
--------
1. Pre-mission provisioning  — RSA public key exchange
2. CHAP authentication       — drone proves identity to GCS
3. DH key exchange           — shared MAC key established
4. Session key distribution  — AES-256 key wrapped with RSA
5. Telemetry transmission    — multiple packets (shows nonce rotation)
6. Attack simulation 1       — Replay Attack       → BLOCKED
7. Attack simulation 2       — MITM Attack         → BLOCKED
"""

import sys
import os
import json

# Ensure repo root is on the path regardless of where we run from
sys.path.insert(0, os.path.dirname(__file__))

from drone          import Drone
from ground_station import GroundStation, SecurityException
from tools          import DroneMessage, DroneStatus
from attacks        import ReplayAttacker, MITMAttacker


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
SHARED_PASSWORD = "Secur3Drone#Pass!"    # pre-shared CHAP secret
DRONE_ID        = "DR001"
MISSION_ID      = "MISSION_ALPHA_001"


# ---------------------------------------------------------------------------
# Pretty-printing helpers
# ---------------------------------------------------------------------------

def banner(title: str) -> None:
    width = 62
    print("\n" + "=" * width)
    print(f"  {title}")
    print("=" * width)

def section(title: str) -> None:
    print(f"\n--- {title} ---")

def show_packet_summary(packet: dict) -> None:
    """Print a condensed, readable summary of a transmitted packet."""
    print("\n  [Packet on the wire]")
    print(f"  ciphertext  : {packet['ciphertext'][:32]}...  ({len(packet['ciphertext'])} chars b64)")
    print(f"  aes_nonce   : {packet['aes_nonce']}")
    print(f"  mac         : {packet['mac'][:32]}...")
    print(f"  signature   : {packet['signature'][:32]}...  ({len(packet['signature'])} chars b64)")
    print(f"  msg_nonce   : {packet['msg_nonce']}")


# ---------------------------------------------------------------------------
# Phase runners
# ---------------------------------------------------------------------------

def phase_provisioning(drone: Drone, gcs: GroundStation) -> None:
    section("Pre-Mission Key Provisioning")
    drone.set_gcs_public_key(gcs.get_public_rsa_key())
    gcs.enroll_drone_public_key(drone.get_public_rsa_key())
    print("  [✓] RSA public keys exchanged and enrolled.")


def phase_authentication(drone: Drone, gcs: GroundStation) -> None:
    section("Phase 1 — CHAP Authentication")
    challenge = gcs.issue_challenge()
    response  = drone.respond_to_challenge(challenge)
    success   = gcs.verify_challenge_response(response)
    if not success:
        raise RuntimeError("Authentication failed — aborting.")


def phase_key_exchange(drone: Drone, gcs: GroundStation) -> None:
    section("Phase 2 — Diffie–Hellman Key Exchange")
    drone_dh_pub = drone.init_dh()
    gcs_dh_pub   = gcs.init_dh()
    # Each side independently derives the same shared MAC key
    drone.complete_dh(gcs_dh_pub)
    gcs.complete_dh(drone_dh_pub)
    print("  [✓] Both sides derived the same shared secret independently.")


def phase_session_key(drone: Drone, gcs: GroundStation) -> None:
    section("Phase 3 — Session Key Distribution (RSA)")
    encrypted_key = drone.generate_and_send_session_key()
    gcs.receive_session_key(encrypted_key)
    print("  [✓] AES-256 session key securely transferred via RSA-OAEP.")


def phase_telemetry(drone: Drone, gcs: GroundStation) -> list[dict]:
    section("Phase 4 — Telemetry Transmission")

    # Telemetry samples representing a drone mid-mission
    messages = [
        DroneMessage(
            drone_id=   DRONE_ID,
            position=   (120.0, 80.0, 45.0),
            velocity=   (3.5, 1.0, 0.0),
            battery_pct=85.2,
            status=     DroneStatus.FLYING,
            mission_id= MISSION_ID,
        ),
        DroneMessage(
            drone_id=   DRONE_ID,
            position=   (135.0, 82.0, 45.0),
            velocity=   (0.0, 0.0, 0.0),
            battery_pct=83.7,
            status=     DroneStatus.HOVERING,
            mission_id= MISSION_ID,
        ),
        DroneMessage(
            drone_id=   DRONE_ID,
            position=   (135.0, 82.0, 5.0),
            velocity=   (0.0, 0.0, -4.0),
            battery_pct=81.1,
            status=     DroneStatus.LANDING,
            mission_id= MISSION_ID,
        ),
    ]

    sent_packets = []
    for i, msg in enumerate(messages, start=1):
        print(f"\n  [Packet {i}] Sending: {msg.pretty()}")
        print(f"  [Packet {i}] JSON  : {msg.to_json()}")
        packet = drone.send_telemetry(msg)
        show_packet_summary(packet)
        gcs.receive_telemetry(packet)
        sent_packets.append(packet)

    return sent_packets


# ---------------------------------------------------------------------------
# Attack simulations
# ---------------------------------------------------------------------------

def simulate_replay_attack(gcs: GroundStation, captured_packet: dict) -> None:
    banner("ATTACK SIMULATION 1 — REPLAY ATTACK")
    print(
        "\n  Scenario: Eve captured packet #1 from the channel.\n"
        "  She re-submits it to the GCS hoping it will be re-processed.\n"
        "  Defence: GCS NonceManager has already seen this nonce.\n"
    )
    attacker = ReplayAttacker()
    attacker.capture(captured_packet)
    attacker.attack(gcs)


def simulate_mitm_attack() -> None:
    banner("ATTACK SIMULATION 2 — MAN-IN-THE-MIDDLE ATTACK")
    print(
        "\n  Scenario: Eve knows the CHAP password and intercepts the DH exchange.\n"
        "  She substitutes her own DH keys and forges a telemetry packet.\n"
        "  She signs it with her own RSA key (she does NOT have the Drone's).\n"
        "  Defence: GCS verifies signature against the pre-enrolled Drone RSA key.\n"
    )

    # Fresh GCS with the REAL drone's public key enrolled
    real_drone = Drone(DRONE_ID, SHARED_PASSWORD)
    fresh_gcs  = GroundStation(SHARED_PASSWORD)

    # Pre-mission: GCS enrolls the real drone's RSA public key
    fresh_gcs.enroll_drone_public_key(real_drone.get_public_rsa_key())
    print(f"\n  [Setup] Fresh GCS created; real Drone '{DRONE_ID}' RSA key enrolled.")
    print("  [Setup] Eve begins impersonation...\n")

    # Eve knows the password, has her own RSA keypair, and intercepts DH
    attacker = MITMAttacker(SHARED_PASSWORD)
    attacker.attack(fresh_gcs, real_drone_mission_id=MISSION_ID)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    banner("SECURE DRONE COMMUNICATION SYSTEM — AD310")
    print(f"\n  Drone ID   : {DRONE_ID}")
    print(f"  Mission    : {MISSION_ID}")
    print(f"  Password   : {'*' * len(SHARED_PASSWORD)}  (pre-shared, never transmitted)")

    # Instantiate the two communicating entities
    drone = Drone(DRONE_ID, SHARED_PASSWORD)
    gcs   = GroundStation(SHARED_PASSWORD)

    # Run the normal secure communication flow
    banner("NORMAL SECURE COMMUNICATION FLOW")
    phase_provisioning(drone, gcs)
    phase_authentication(drone, gcs)
    phase_key_exchange(drone, gcs)
    phase_session_key(drone, gcs)
    packets = phase_telemetry(drone, gcs)

    print("\n  [✓] All telemetry packets received, verified, and decrypted successfully.")

    # Run attack simulations
    simulate_replay_attack(gcs, packets[0])   # use the first accepted packet
    simulate_mitm_attack()

    # Final summary
    banner("SUMMARY")
    print(
        "\n  Security properties demonstrated:\n"
        "  ✓  Confidentiality    — AES-256-CTR encrypts all telemetry data\n"
        "  ✓  Authentication     — CHAP challenge-response (password never sent)\n"
        "  ✓  Key exchange       — Diffie–Hellman (2048-bit MODP Group 14)\n"
        "  ✓  Forward secrecy    — ephemeral DH keys; new session key each run\n"
        "  ✓  Integrity          — HMAC-SHA256 (Encrypt-then-MAC)\n"
        "  ✓  Non-repudiation    — RSA-PSS-SHA256 digital signatures\n"
        "  ✓  Replay protection  — UUID4 nonce registry (NonceManager)\n"
        "  ✓  MITM resistance    — RSA signature binds message to enrolled Drone\n"
    )


if __name__ == "__main__":
    main()
