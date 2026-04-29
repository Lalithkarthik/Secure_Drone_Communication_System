"""
ground_station.py

This is the server side of the system, which authenticates the client side, which is the Drone, and receives messages transmitted over the
medium. The functions this file facilities the use of are the tasks that the Ground Station is required to perform:
1. Initialise - The Ground Station class object, when created from the main.py file, initialises a Ground Station.
2. Authentication - Issues a challenge to the Drone to validate it. Once the response is received, it performs the same challenge itself
using the password to ensure that the response is the same to successfully authenticate the Drone.
3. Diffie Hellman - Key exchange is followed and keys are exchanged with the Drone, which are later used to generate MAC
4. AES Session Key - The session key generated and encrypted through RSA is received and is decrypted to obtain the actual AES key.
5. Message receiving - Upon receiving the packets from the Drone, it performs a few sub-task for validation and security purposes, and also
to obtain the plaintext:
    a. It computes the MAC itself and ensures the shared and computed MACs are the same (integrity)
    b. Checks Nonce using the NonceManager (tools/replay_protection.py) to ensure uniqueness of the nonce (replay protection)
    c. Once the attcks seem to be prevented, the message is decrypted using the AES session key (recover plaintext)
    d. The RSA digital signature is then verified for checking identity of sender (authentication, non-repudiation, and MITM attack prevention)
    e. Message is then deserialised.
"""

from time import sleep
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey

from tools import (
    CHAPAuthenticator,
    DHParty,
    DroneMessage,
    HybridEncryptor,
    MACHandler,
    NonceManager,
    PasswordStore,
    RSA_Signer,
)

class SecurityException(Exception):
    """
    Raised whenever any check fails during packet processing, like incorrect MAC, failed authentication, repeated nonce, etc. Raised to 
    log what exactly the issue is appropriately.
    """
    pass

class GroundStation:
    """
    Class representing the actual Ground Station in our system. It is initialised with the password required for authentication.
    """
    
    def __init__(self, password: str):
        self.password = password

        #The plaintext password is only used for direct initialisations, isn't considered direct storage. The passwords are stored with
        #the ground station in a class called "PasswordStore" from tools/authentication.py. These passwords are not directly stored, but
        #are hashed and salted and then stored. They are never directly used for authentication, printing, or any other function.
        self._pw_store = PasswordStore()
        self._pw_salt, self._pw_hash = self._pw_store.hash_password(password)

        self.rsa_private, self.rsa_public = RSA_Signer.generate_keypair() #Generate the Ground Station's private and public RSA keys
        self.chap = CHAPAuthenticator() #Authenticating class from tools.authentication.py initialised

        #The following variables are populated over the course of communication
        self.drone_public_rsa: RSAPublicKey | None = None
        self.dh: DHParty | None = None
        self.mac_key: bytes   | None = None
        self._session_key: bytes   | None = None

        self.nonce_manager = NonceManager() #Manages the nonce viewed across all packets within the session. Critical for detecting replay attacks.
        self.authenticated = False
        sleep(1)
        print("[Ground Station] Ground Control Station initialised - public and private RSA keypair generated.")

    def get_public_rsa_key(self) -> RSAPublicKey:
        """
        Shares the Ground Station's RSA public key to the Drone.
        """
        return self.rsa_public

    def enroll_drone_public_key(self, drone_public_key: RSAPublicKey) -> None:
        """
        Receives the Drone's RSA public key and stores it. Used for checking the digital signature.
        """
        self.drone_public_rsa = drone_public_key
        print("[Ground Station] Drone RSA public key enrolled.")

    def issue_challenge(self) -> bytes:
        """
        Issues a challenge to authenticate a Drone. Drone needs to complete this challenge with it's password successfully for authentication.
        A new random challenge every single time is used and solved by the Ground Station simultaneously, using the stored password, and the
        result is used appropriately for verification.
        """
        challenge = self.chap.generate_challenge()
        sleep(1)
        print(f"[Ground Station] CHAP challenge issued: {challenge.hex()}")
        return challenge

    def verify_challenge_response(self, response: bytes) -> bool:
        """
        Receives the Drone's response to the above CHAP challenge. Computes the challenge itself and compares the result with the Drone's 
        submission. Confirmation leads to authentication, while failure leads to the Drone being considered malicious as it has failed to
        successfuly authenticate itself.
        """
        sleep(1)
        result = self.chap.verify_response(response, self.password)
        if result:
            self.authenticated = True
            print("[Ground Station] CHAP authentication: PASSED. Drone has been authenticated successfully.")
        else:
            print("[Ground Station] CHAP authentication: FAILED. Drone has failed the authentication challenge")
        return result

    def init_dh(self) -> int:
        """
        Generates a DH keypair. Exchange occurs with the next function.
        """
        self.dh = DHParty()
        public = self.dh.get_public_int()
        sleep(1)
        print("[Ground Station] DH keypair generated.")
        return public

    def complete_dh(self, drone_dh_public: int) -> None:
        """
        Exchange is performed with the Ground Station's key, to finally obtain the key for generating the MAC.
        """
        if self.dh is None:
            raise RuntimeError("Call init_dh() before complete_dh().")
        derived = self.dh.derive_shared_key(drone_dh_public)
        self.mac_key = derived[:16] #The first 16 characters of the exchanged key are used for MAC in our implementation. Rest can be considered to be additional, potentially used later for future applications.
        sleep(1)
        print("[Ground Station] DH exchange complete - MAC key derived.")

    def receive_session_key(self, encrypted_session_key: bytes) -> None:
        """
        Receives and decrypts the RSA-wrapped AES session key generated and sent by the Drone. Uses own RSA private key for
        decryption of the same.
        """
        self._session_key = HybridEncryptor.rsa_decrypt_key(encrypted_session_key, self.rsa_private)
        sleep(1)
        print("[Ground Station] AES-256 session key unwrapped successfully. \n[Ground Station] Session initialised. " \
        "[Ground Station] \nChannel open for communication.")

    def receive_message(self, packet: dict) -> DroneMessage:
        """
        The packet is received from the Drone as a dictionary, which needs to be converted to the appropriate DroneMessage class, 
        representing the actual message, which involves a few processing steps:
        1. Authentication check to verify whether the sender has been authenticated
        2. MAC verification to ensure integrity of message
        3. Nonce check to prevent replay attacks
        4. AES decryption to recover the plaintext
        5. Digital signature check to verify identity of sender
        """
        sleep(1)
        if not self.authenticated:
            raise SecurityException("Drone is not authenticated.") #Checks to ensure the Drone has been authenticated successfully.
        #Obtains all values from the received packet
        ciphertext = packet["ciphertext"]
        aes_nonce = packet["aes_nonce"]
        mac = packet["mac"]
        signature = packet["signature"]
        msg_nonce: str = packet["msg_nonce"]

        #Checks for the integrity of the message by verifying the MAC
        if not MACHandler.verify(ciphertext + aes_nonce, self.mac_key, mac):
            raise SecurityException("MAC verification FAILED - message was tampered with in transit. Message integrity compromised.")
        print("[Ground Station] Integrity check passed. Task 3.5 achieved.")
        sleep(1)

        #Checks whether the nonce is unique or has been repeated during the current session. Protects against replay attacks
        if not self.nonce_manager.register_nonce(msg_nonce):
            raise SecurityException(f"REPLAY ATTACK detected - nonce '{msg_nonce}' has already been processed.")
        print("[Ground Station] Nonce is fresh - not a replay. Task 3.6 achieved.")
        sleep(1)

        plaintext = HybridEncryptor.aes_decrypt(ciphertext, self._session_key, aes_nonce) #Decrypts the plaintext from the ciphertext using the AES key.
        print("[Ground Station] AES decryption successful.")
        sleep(1)

        #Checks the Digital Signature in the message to verify sender identity.
        if self.drone_public_rsa is None:
            raise SecurityException("No drone RSA public key enrolled.")
        if not RSA_Signer.verify(plaintext, signature, self.drone_public_rsa):
            raise SecurityException("RSA signature verification FAILED - possible forgery or MITM attack.")
        print("[Ground Station] RSA digital signature verified. Task 3.4 achieved.")
        sleep(1)

        #At this point, all checks have passed, so the Ground Station accepts the message.
        message = DroneMessage.from_json(plaintext.decode("utf-8"))
        print(f"[Ground Station] Telemetry accepted: {message.printer()}")
        return message
