# Secure Drone Communication System

A secure end-to-end communication framework for unmanned aerial systems (UAS), designed to protect telemetry exchange between a Drone and a Ground Control Station (GCS). The system integrates modern cryptographic primitives to provide confidentiality, authentication, integrity, non-repudiation, and replay-attack protection.

---

## Overview

Drone communication channels are vulnerable to eavesdropping, message tampering, spoofing, and replay attacks. This project implements a layered security architecture that secures telemetry transmission through authenticated key exchange, hybrid encryption, digital signatures, and integrity verification.

The system simulates a real-world drone communication workflow in which telemetry data is securely transmitted from a drone to a ground station while preventing unauthorized access and malicious manipulation.

---

## Key Features

### Secure Key Exchange
- Elliptic Curve Cryptography (ECC) based key exchange
- Shared secret generation between drone and ground station
- Secure session establishment without transmitting secret keys

### Hybrid Encryption
- RSA used for secure session-key exchange
- AES used for high-performance payload encryption
- Protects telemetry data against interception

### Authentication
- Secure authentication mechanism
- Password hashing and salting
- Prevents unauthorized device access

### Digital Signatures
- Message signing using asymmetric cryptography
- Signature verification at the receiver
- Provides authenticity and non-repudiation

### Message Integrity
- HMAC-SHA256 based integrity verification
- Detects message modification during transmission

### Replay Attack Protection
- Timestamp and nonce validation
- Rejects duplicate and stale messages

---

## System Workflow

```text
Drone
  │
  ├── Authentication
  │
  ├── ECC Key Exchange
  │
  ├── AES Session Key Establishment
  │
  ├── Encrypt Telemetry Data
  │
  ├── Generate HMAC
  │
  ├── Sign Message
  │
  └── Send Secure Packet
          │
          ▼
Ground Control Station
  │
  ├── Verify Authentication
  ├── Verify Signature
  ├── Verify HMAC
  ├── Validate Timestamp/Nonce
  └── Decrypt Telemetry Data
```

---

## Security Architecture

| Security Requirement | Implementation |
|----------------------|---------------|
| Confidentiality | AES Encryption |
| Secure Key Distribution | RSA / ECC |
| Authentication | Password Hashing + Salt |
| Integrity | HMAC-SHA256 |
| Non-Repudiation | Digital Signatures |
| Replay Protection | Timestamp / Nonce Validation |

---

## Example Telemetry Payload

```json
{
  "drone_id": "DR001",
  "latitude": 12.97,
  "longitude": 77.59,
  "speed": 45
}
```

---

## Project Structure

```text
Secure_Drone_Communication_System/
│
├── authentication.py
├── key_exchange.py
├── encryption.py
├── signature.py
├── integrity.py
├── replay_protection.py
├── drone.py
├── ground_station.py
├── main.py
│
└── README.md
```

---

## Technologies Used

- Python
- Cryptography
- PyCryptodome
- AES
- RSA
- ECC
- SHA-256
- HMAC
- Secure Key Exchange

---

## Threats Mitigated

### Eavesdropping
AES encryption ensures transmitted telemetry cannot be read by unauthorized parties.

### Message Tampering
HMAC verification detects any modification of data in transit.

### Spoofing
Authentication and digital signatures prevent impersonation of legitimate devices.

### Replay Attacks
Timestamp and nonce validation reject duplicated packets.

### Man-in-the-Middle Attacks
Secure key exchange and signature verification protect session establishment.

---

## Future Improvements

- Mutual certificate-based authentication
- Hardware-backed key storage
- TLS-secured communication channels
- Multi-drone network support
- Real-time intrusion detection and anomaly monitoring
- Integration with MAVLink and PX4/ArduPilot ecosystems

---

## Demonstrations

This project demonstrates practical implementation of:

- Symmetric Cryptography
- Asymmetric Cryptography
- Hybrid Encryption Systems
- Secure Key Exchange
- Digital Signatures
- Authentication Protocols
- Message Integrity Verification
- Replay-Attack Prevention
- Secure Communication Protocol Design
