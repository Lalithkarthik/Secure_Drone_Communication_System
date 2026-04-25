"""
main.py
=======
Secure Drone Communication System - Demo Entry Point

Run with:   python main.py

Sequence
--------
1. Pre-mission provisioning  - RSA public key exchange
2. CHAP authentication       - drone proves identity to GCS
3. DH key exchange           - shared MAC key established
4. Session key distribution  - AES-256 key wrapped with RSA
5. Telemetry transmission    - multiple packets (shows nonce rotation)
6. Attack simulation 1       - Replay Attack       → BLOCKED
7. Attack simulation 2       - MITM Attack         → BLOCKED
"""

from drone import Drone
from ground_station import GroundStation, SecurityException
from tools import DroneMessage, DroneStatus
from attacks import ReplayAttacker, MITMAttacker

#Drone Configuration
DRONE_ID = "ALPHA_007"
SHARED_PASSWORD = "7thNe^erF@!ls"    #pre-shared password for authentication
MISSION_ID = "MISSION_SCOUT_V7"

#Helpers for the sequential execution of proper communication flow

def rsa_key_exchange(drone: Drone, gcs: GroundStation) -> None:
    """
    Provides the Drone and Ground Station with each other's public keys. 
    """
    print("\nRSA Keys being exchanged between Drone and Ground Station...")
    drone.set_gcs_public_key(gcs.get_public_rsa_key())
    gcs.enroll_drone_public_key(drone.get_public_rsa_key())
    print("RSA public keys exchanged and enrolled successfully.")


def drone_gcs_authentication(drone: Drone, gcs: GroundStation) -> None:
    """
    Authentication between the drone and ground station in a format same as the challenge handshake protocol.
    """
    print("\nPhase 1 - CHAP Authentication")
    challenge = gcs.issue_challenge()
    response = drone.respond_to_challenge(challenge)
    success = gcs.verify_challenge_response(response)
    if not success:
        raise RuntimeError("Authentication failed - Rouge Drone identified. Aborting mission.") #Would run if the pre-shared passwords aren't the same.


def phase_key_exchange(drone: Drone, gcs: GroundStation) -> None:
    print("\nPhase 2 - Diffie–Hellman Key Exchange")
    drone_dh_pub = drone.init_dh()
    gcs_dh_pub   = gcs.init_dh()
    # Each side independently derives the same shared MAC key
    drone.complete_dh(gcs_dh_pub)
    gcs.complete_dh(drone_dh_pub)
    print("  Both sides derived the same shared secret independently.")


def phase_session_key(drone: Drone, gcs: GroundStation) -> None:
    print("\nPhase 3 - Session Key Distribution (RSA)")
    encrypted_key = drone.generate_and_send_session_key()
    gcs.receive_session_key(encrypted_key)
    print("  AES-256 session key securely transferred via RSA-OAEP.")


def phase_telemetry(drone: Drone, gcs: GroundStation) -> list[dict]:
    print("\nPhase 4 - Telemetry Transmission")

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

        print("\n  [Packet on the wire]")
        print(f"  ciphertext  : {packet['ciphertext'][:32]}...  ({len(packet['ciphertext'])} chars b64)")
        print(f"  aes_nonce   : {packet['aes_nonce']}")
        print(f"  mac         : {packet['mac'][:32]}...")
        print(f"  signature   : {packet['signature'][:32]}...  ({len(packet['signature'])} chars b64)")
        print(f"  msg_nonce   : {packet['msg_nonce']}")

        gcs.receive_telemetry(packet)
        sent_packets.append(packet)

    return sent_packets


# ---------------------------------------------------------------------------
# Attack simulations
# ---------------------------------------------------------------------------

def simulate_replay_attack(gcs: GroundStation, captured_packet: dict) -> None:
    print("ATTACK SIMULATION 1 - REPLAY ATTACK")
    print("A cryptanalyst has captured packet #1 from the channel and tries re-submitting it to the Ground Station, creating a replay attack.\n")
    attacker = ReplayAttacker()
    attacker.capture(captured_packet)
    attacker.attack(gcs)


def simulate_mitm_attack() -> None:
    print("ATTACK SIMULATION 2 - MAN-IN-THE-MIDDLE ATTACK")
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
    """
    Executes the entire communication system between the drone and the ground station. Also simulates the attacks and shows the
    system's capability to deal with them.
    """

    print("SECURE DRONE COMMUNICATION SYSTEM")
    print(f"Drone ID   : {DRONE_ID}")
    print(f"Mission    : {MISSION_ID}")
    print(f"Password   : {SHARED_PASSWORD}\n") #The password is used to initialise both drone and ground station and works for authenticating the devices and establishing the connection.

    #Initialise both drone and ground station.
    drone = Drone(DRONE_ID, SHARED_PASSWORD)
    ground_station = GroundStation(SHARED_PASSWORD) #Passwords passed to both drone and ground station - assume pre-defined.

    #The regular communication flow is executed.
    print("\nCOMMUNICATION:")
    rsa_key_exchange(drone, ground_station)
    drone_gcs_authentication(drone, ground_station)
    phase_key_exchange(drone, ground_station)
    phase_session_key(drone, ground_station)
    packets = phase_telemetry(drone, ground_station)

    print("\nAll telemetry packets received, verified, and decrypted successfully.\nCOMPLETE COMMUNICATION SUCCESSFUL.\n")

    #Both replay and mitm attacks are simulated.
    simulate_replay_attack(ground_station, packets[0]) #Replay attack is simulated using the first accepted packet, which is assumed to be known to cryptanalyst.
    simulate_mitm_attack()

if __name__ == "__main__":
    main()
