"""
attacks/mitm_attack.py

This file handles the simulation of the MITM attack. An attacker inserts herself between the Drone and the Ground Station, intercepting the 
DH key exchange and substitutes her own DH keys, giving separate access to both the Drone and the Ground Station, potentially directing
traffic on both sides, with neither having any knowledge of the attacker's presence and actions. But this attack is prevented by our
implementation of the Digital Signature. It is assumed that the Ground Station has access to the real Drone's RSA key being used for digital
signature. The Drone continues to sign with its own private key, but the attacker cannot modify or tamper this aspect. Due to this, when
the Ground Station tries verifying the identity of the sender, the Ground Station figures out that there is a signature mismatch between the
message signature and the sender, thus protecting against such MITM attacks. But this attack simulation requires a few more processing steps
compared to the replay attack:
1. A fresh Ground Station is created only upto the step of having the Drone's real RSA public key enrolled. This is because all 
subsequent steps have the presence of the attacker, which is also why having a fresh Ground Station is required for this task.
2. The subsequent steps are completed by the attacker like DH key exchange, creation and sharing AES session key, forging message packets, 
signing with own RSA private key and sharing the packets. The Attacker essentially mimics the entire flow in place of the drone.
"""

import os
from time import sleep

from ground_station import GroundStation, SecurityException
from tools import (
    CHAPAuthenticator,
    DHParty,
    DroneMessage,
    DroneStatus,
    HybridEncryptor,
    MACHandler,
    RSA_Signer,
)

class MITMAttacker:
    """
    Simulates an active Man-in-the-Middle attacker who knows the CHAP password and can thus authenticate herself. Owns her own DH and 
    RSA key pairs and successfully shares them with the Ground Station, acting like the drone. The only detail missing is the legitimate
    Drone's RSA private key which is used for digital signature, while the Ground Station is in possession of the actual drone's RSA
    public key, and hence is able to figure out there is an identity issue of the sender, thus preventing the attack.
    """

    def __init__(self, password: str):
        """
        The pre-shared CHAP password is assumed to have obtained this somehow.
        """
        self.password = password #Same as the password shared between Drone and Ground Station, which the cryptanalyst has figured out.

        #Cryptanalyst creates and uses her own RSA keys
        self.rsa_private_key, self.rsa_public_key = RSA_Signer.generate_keypair()

        #Cryptanalyst does not have access to the AES session key, or the key to generate the MAC.
        self.session_key: bytes | None  = None
        self.mac_key: bytes | None  = None
        sleep(1)
        print("[MITM Attacker] Initialised with own RSA keypair.")

    def attack(self, gs: GroundStation, mission: str) -> None:
        """
        Attempts a full MITM impersonation of the Drone through the following steps:
        1. Authenticate itself with the Ground Station using the known password.
        2. Perform DH key exchange with Ground Station using own DH keys.
        3. Generate own AES session key, wrap with Ground Station's RSA public key and share it.
        4. Construct a forged DroneMessage.
        5. Sign with own RSA private key (but not the real Drone's, which is the critical reason due to which MITM attack is blocked).
        6. Encrypt, MAC, and transmit message to the ground station.
        """
        print("[MITM Attacker] Starting impersonation of Drone...")
        #Cryptanalyst knows the password, so can successfully authenticate with the ground station, posing as the drone
        challenge = gs.issue_challenge()
        response = CHAPAuthenticator.compute_response(challenge, self.password)
        auth_ok = gs.verify_challenge_response(response)
        if not auth_ok:
            print("[MITM Attacker] CHAP failed - cannot proceed.")
            return
        sleep(1)
        print("[MITM Attacker] CHAP passed (password known). Proceeding...")

        #Cryptanalyst proceeds to exchange her own keys with the Ground Station
        cryptanalyst_dh = DHParty()
        cryptanalyst_dh_public  = cryptanalyst_dh.get_public_int()
        gs_dh_public = gs.init_dh()
        gs.complete_dh(cryptanalyst_dh_public) #gs unknowingly exchanges keys with the cryptanalyst, assuming the identity to be the drone.
        mac_key_derived = cryptanalyst_dh.derive_shared_key(gs_dh_public)
        self.mac_key = mac_key_derived[:16] #Using this, the cryptanalyst successfully derives the key for MAC
        sleep(1)
        print("[MITM Attacker] DH exchange complete. Now has the key for the MAC.")

        #Cryptanalyst proceeds to create a fake AES session key and share it with the gs
        self.session_key = os.urandom(32)
        enc_key = HybridEncryptor.rsa_encrypt_key(self.session_key, gs.get_public_rsa_key())
        gs.receive_session_key(enc_key)
        sleep(1)
        print("[MITM Attacker] Fake AES session key sent to gs.")

        #Now, cryptanalyst forges messages to seem they are from the drone. The message gives the information of forged "landing" command, and maliciously gives 
        #incorrect information of the sensitive "Drone Status" to the Ground Station.
        forged_msg = DroneMessage(
            drone_id = "DR001",                 
            position = (50.0, 50.0, 10.0),
            velocity = (0.0, 0.0, -5.0),             
            battery_pct = 99.0,
            status = DroneStatus.LANDING,  
            mission_id = mission,
        )
        plaintext = forged_msg.to_json().encode("utf-8")
        sleep(1)
        print(f"[MITM Attacker] Forged message ready: {forged_msg.printer()}")

        #Cryptanalyst continues the normal communication flow of signing with it's own RSA key, encrypting and applying MAC correctly 
        #and submit to the gs
        forged_signature = RSA_Signer.sign(plaintext, self.rsa_private_key)
        sleep(1)
        print("[MITM Attacker] Digital signature with own RSA key (not the same as enrolled Drone key).") #This is the reason due to which
        #the gs is able to identify the attack
        ciphertext, aes_nonce = HybridEncryptor.aes_encrypt(plaintext, self.session_key)
        mac = MACHandler.generate(ciphertext + aes_nonce, self.mac_key)
        forged_packet = {
            "ciphertext": ciphertext,
            "aes_nonce": aes_nonce,
            "mac": mac,
            "signature": forged_signature,
            "msg_nonce": forged_msg.nonce,
        }
        print("[MITM Attacker] Submitting forged packet to Ground Station...")
        sleep(1)
        try:
            gs.receive_message(forged_packet)
            print("[MITM Attacker] MITM SUCCEEDED - WE BROKE THE SYSTEM !!")
        except SecurityException as exc:
            sleep(1)
            print(f"\n[Ground Station] MITM attack BLOCKED: {exc}")
            print("SYSTEM SECURE.")
