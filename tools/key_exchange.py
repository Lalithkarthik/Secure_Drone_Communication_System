"""
key_exchange.py
=====================
Diffie–Hellman Key Exchange using RFC 3526 Group 14 (2048-bit MODP).

Design
------
DHParty represents one side of the exchange (either Drone or GCS).
Both parties use the same well-known safe prime (p, g).
The shared secret is never used directly — HKDF-SHA256 derives a
strong 32-byte key from it.

Usage
-----
    drone_dh = DHParty()
    gcs_dh   = DHParty()

    # Exchange public integers (these are safe to send in the clear)
    drone_pub = drone_dh.get_public_int()
    gcs_pub   = gcs_dh.get_public_int()

    # Each side independently derives the same 32-byte key
    drone_key = drone_dh.derive_shared_key(gcs_pub)
    gcs_key   = gcs_dh.derive_shared_key(drone_pub)

    assert drone_key == gcs_key   # True
"""

from cryptography.hazmat.primitives.asymmetric.dh import (
    DHParameterNumbers,
    DHPublicNumbers,
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes


# ---------------------------------------------------------------------------
# RFC 3526 – Group 14: 2048-bit MODP safe prime (p) and generator (g = 2).
# Using a standardised group means both parties need no extra negotiation.
# ---------------------------------------------------------------------------
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
    One participant in a Diffie–Hellman key exchange.

    Each instance generates a fresh ephemeral private key from the shared
    RFC 3526 Group 14 parameters.  Call get_public_int() to retrieve the
    value to send to the peer, then derive_shared_key() once the peer's
    public integer has been received.

    Attributes
    ----------
    shared_key  : the 32-byte derived key (available after derive_shared_key)
    """

    # Class-level parameters — built once, shared across all instances.
    _PARAMS = _build_dh_parameters()

    def __init__(self):
        self._private_key   = DHParty._PARAMS.generate_private_key()
        self._shared_key: bytes | None = None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def get_public_int(self) -> int:
        """Return this party's DH public value as a plain integer."""
        return self._private_key.public_key().public_numbers().y

    def derive_shared_key(self, peer_public_int: int) -> bytes:
        """
        Compute the shared secret from the peer's public integer and
        derive a 32-byte symmetric key via HKDF-SHA256.

        Parameters
        ----------
        peer_public_int : the integer received from the other party

        Returns
        -------
        32-byte derived key (also stored as self._shared_key)
        """
        # Reconstruct the peer's DHPublicKey from the raw y value
        peer_pub_numbers = DHPublicNumbers(
            y=peer_public_int,
            parameter_numbers=DHParty._PARAMS.parameter_numbers(),
        )
        peer_pub_key = peer_pub_numbers.public_key()

        # DH exchange → raw shared secret bytes
        raw_secret = self._private_key.exchange(peer_pub_key)

        # HKDF stretches and mixes the raw secret into a uniform key
        self._shared_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"drone-gcs-dh-session-v1",
        ).derive(raw_secret)

        return self._shared_key

    @property
    def shared_key(self) -> bytes:
        """The derived key is returned and shared as needed."""
        if self._shared_key is None:
            raise RuntimeError("derive_shared_key() has not been called yet.")
        return self._shared_key
