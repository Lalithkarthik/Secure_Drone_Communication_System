"""
drone.py

This is the client side of the system, which authenticates itself with the admin side, which is the Ground Station, and transmits messages
to it. The functions this file facilities the use of are the tasks that the Drone is required to perform:
1. Initialisation - The main.py creates a Drone class object, which acts as our Drone, with a known password
2. Authentication - The Drone receives the Ground Station's challenge, solves it using it's password, and sends the response back, in a
CHAP style authentication protocol
3. Diffie Hellman - Key exchange is followed and keys are exchanged with the Ground Station, which are later used to generate MAC
4. AES Session key - The Drone takes responsibility for generating an AES-256 session key and shares it with the Ground Station securely 
by wrapping it with the Ground Station's RSA.
5. Message Transmission - After the entire setup is complete, the Drone starts communication by sharing packets with the Ground Station
over the medium which involve the following sub-tasks:
    a. Serialise to JSON for ease of handling
    b. Digital Signature with Drone's own RSA private key (authenticity and non-repudiation)
    c. Encryption with the AES session key (confidentiality)
    d. MAC generated over the ciphertext, along with nonce, which form the core of the message required for transmission (integrity)
    e. The final message is formed as a dictionary and shared.
"""

import os
from time import sleep
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey

from tools import (
    CHAPAuthenticator,
    DHParty,
    DroneMessage,
    HybridEncryptor,
    MACHandler,
    RSA_Signer,
)

class Drone:
    """
    Class representing the actual drone in our system. It is initialised with the Drone ID and the password required for authentication.
    """

    def __init__(self, drone_id: str, password: str):
        self.drone_id = drone_id
        self.password = password
        print(f"Starting up the Drone {drone_id}...")
        sleep(1)

        print("Generating Drone's RSA public and private keys...")
        sleep(1) 
        self.rsa_private_key, self.rsa_public_key = RSA_Signer.generate_keypair() #Generates its own RSA public and private keys
        print(f"Generated Drone {drone_id}'s RSA keys successfully.")

        #The following variables are populated during the system simulation
        self.gs_public: RSAPublicKey | None = None
        self.dh: DHParty | None = None
        self.aes_session_key: bytes | None = None
        self.mac_key: bytes | None = None

        print(f"[Drone {self.drone_id} reporting] En route the Mission.")

    def get_public_rsa_key(self) -> RSAPublicKey:
        """
        Returns Drone's RSA public key for the Ground Station to use.
        """
        return self.rsa_public_key

    def set_gs_public_key(self, gs_public_key: RSAPublicKey) -> None:
        """
        Obtains the Ground Station's RSA public key and stores it.
        """
        self.gs_public = gs_public_key
        print(f"[Drone {self.drone_id}] gs RSA public key stored.")

    def respond_to_challenge(self, challenge: bytes) -> bytes:
        """
        Compute the CHAP response for the given challenge and passes it back to the Ground Station for authentication, without the password
        ever being transmitted directly.
        """
        response = CHAPAuthenticator.compute_response(challenge, self.password)
        sleep(1)
        print(f"[Drone {self.drone_id}] CHAP response computed.")
        return response

    def init_dh(self) -> int:
        """
        Generates a DH keypair. Exchange occurs with the next function.
        """
        self.dh = DHParty()
        public_key = self.dh.get_public_int()
        print(f"[Drone {self.drone_id}] DH keypair generated.")
        return public_key

    def complete_dh(self, gs_dh_public: int) -> None:
        """
        Exchange is performed with the Ground Station's key, to finally obtain the key for generating the MAC.
        """
        if self.dh is None:
            raise RuntimeError("Call init_dh() before complete_dh().")
        derived = self.dh.derive_shared_key(gs_dh_public)
        self.mac_key = derived[:16] #The first 16 characters of the exchanged key are used for MAC in our implementation. Rest can be considered to be additional, potentially used later for future applications.
        sleep(1)
        print(f"[Drone {self.drone_id}] DH exchange complete - MAC key derived.")

    def generate_and_send_session_key(self) -> bytes:
        """
        Generation of AES-256 session key is done by the Drone, and is securely transmitted to the Ground Station using RSA.
        """
        if self.gs_public is None:
            raise RuntimeError("gs RSA public key not set.")

        self.aes_session_key  = os.urandom(32)
        encrypted_key = HybridEncryptor.rsa_encrypt_key(self.aes_session_key, self.gs_public)
        sleep(1)
        print(f"[Drone {self.drone_id}] AES-256 session key generated and RSA-wrapped. Sending securely to the Ground Station...")
        return encrypted_key
    
    def send_message(self, message: DroneMessage) -> dict:
        """
        The message of DroneMessage class (from tools/message.py) is packaged into a proper packet after a few processing steps:
        1. Serialise to JSON
        2. Sign with RSA private key
        3. Encrypt with AES-256 session key
        4. Add MAC over the ciphertext
        """
        if self.aes_session_key is None:
            raise RuntimeError("Session key not set - complete key exchange first.")
        if self.mac_key is None:
            raise RuntimeError("MAC key not set - complete DH exchange first.")

        plaintext = message.to_json().encode("utf-8") #Encoded into the prescribed format (from message.py)
        signature = RSA_Signer.sign(plaintext, self.rsa_private_key) #Digital signature using RSA
        ciphertext, aes_nonce = HybridEncryptor.aes_encrypt(plaintext, self.aes_session_key) #Encrypted with AES and it's nonce generated
        mac = MACHandler.generate(ciphertext + aes_nonce, self.mac_key) #MAC generated
        packet = {
            "ciphertext" : ciphertext,
            "aes_nonce"  : aes_nonce,
            "mac"        : mac,
            "signature"  : signature,
            "msg_nonce"  : message.nonce  #plaintext nonce for replay check
        } 
        sleep(1)
        print(f"[Drone {self.drone_id}] Secure packet assembled. Transmitting...")
        return packet
