"""
tools/key_exchange.py

This file implementes the Diffie Hellman Key exchange. DHParty represents one side of the exchange (either Drone or Ground Station).
Both parties use the same well-known prime, generator pair (p, g). The shared secret is never used directly, although a key is derived 
from it. Both parties (Drone and Ground Station are initialised) after which the integesrs are exchange, and the keys are derived 
independently by each part, but it leads to the same key, and essentially functions as key-exchange.
"""

from cryptography.hazmat.primitives.asymmetric.dh import (
    DHParameterNumbers,
    DHPublicNumbers,
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

#RFC 3526 – Group 14: 2048-bit MODP safe prime (p) and generator (g = 2). Required for the implementation
_P = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
    "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
    "83655D23DCA3AD961C62F356208552BB9ED52907709696"
    "6D670C354E4ABC9804F1746C08CA18217C32905E462E36CE"
    "3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52"
    "C9DE2BCBF6955817183995497CEA956AE515D2261898FA05"
    "1015728E5A8AACAA68FFFFFFFFFFFFFFFF",
    16,
)
_G = 2

def _build_dh_parameters():
    """Build the shared DH parameter object once at module load."""
    return DHParameterNumbers(_P, _G).parameters()

class DHParty:
    """
    One participant in a Diffie–Hellman key exchange - either the Drone or Ground Station. Each instance generates a fresh ephemeral 
    private key from the shared RFC 3526 Group 14 parameters. Functions get_public_int() exist to retrieve the value to send to the peer, 
    after which the function derive_shared_key() can be used once the peer's public integer has been received.
    """

    #The parameters of P and G are instanitated.
    _PARAMS = _build_dh_parameters()

    def __init__(self):
        self._private_key = DHParty._PARAMS.generate_private_key()
        self._shared_key: bytes | None = None

    def get_public_int(self) -> int:
        """
        Returns a particular party's DH public value as a plain integer.
        """
        return self._private_key.public_key().public_numbers().y

    def derive_shared_key(self, peer_public_int: int) -> bytes:
        """
        Computes the shared secret from the peer's public integer and derives a 32-byte symmetric key.
        """
        #Reconstructs the peer's DH Public Key from the raw y value
        peer_pub_numbers = DHPublicNumbers(y=peer_public_int, parameter_numbers=DHParty._PARAMS.parameter_numbers())
        peer_pub_key = peer_pub_numbers.public_key()
        raw_secret = self._private_key.exchange(peer_pub_key) #DH exchange

        #HKDF stretches and mixes the raw secret into a uniform key
        self._shared_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"drone-gs-dh-session-v1",
        ).derive(raw_secret)

        return self._shared_key

    @property
    def shared_key(self) -> bytes:
        """
        The derived key is returned and shared as needed.
        """
        if self._shared_key is None:
            raise RuntimeError("derive_shared_key() has not been called yet.")
        return self._shared_key
