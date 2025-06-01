# Vehicular PKI Simulation Project

This project simulates a Vehicular Public Key Infrastructure (VPKI) system, implementing the main entities and protocols for secure and privacy-preserving communication between vehicles and authorities. It follows standards such as ETSI 103 097 and IEEE 1609.2 for certificate management and message encoding.

---

## Table of Contents

- [Overview](#overview)
- [Project Structure](#project-structure)
- [Main Components](#main-components)
  - [Entities](#entities)
  - [Addressing](#addressing)
  - [Certificate Management](#certificate-management)
  - [Communication](#communication)
- [Simulation Workflow](#simulation-workflow)
- [How to Run](#how-to-run)
- [ASN.1 Schemas](#asn1-schemas)
- [Customization](#customization)
- [Development Notes](#development-notes)
- [License](#license)

---

## Overview

The project models a VPKI system with the following entities:

- **Registration Authority (RA)**
- **Long-Term Certificate Authority (LTCA)**
- **Pseudonym Certificate Authority (PCA)**
- **Link Authorities (LA1, LA2)**
- **Vehicles (VEH, VEH2, ...)**

Each entity is implemented as a Python class, running as a service and communicating via local sockets. The system supports certificate issuance, pseudonym management, and revocation, simulating real-world vehicular network security operations.

---

## Project Structure

```
develop/
│   __main__.py                # Main simulation script
│   generate_root_cert.py      # Root CA certificate/key generation
│   README.md                  # This documentation
│   requirements.txt           # Python dependencies
│
├── asn/
│     Etsi_flattened.asn       # ETSI ASN.1 schema
│     Ieee1609Dot2BaseTypes.asn# IEEE ASN.1 schema
│
├── ca/
│     root_ca.cert             # Root CA certificate
│     root_ca.key.pem          # Root CA private key
│     root_ca.pub.pem          # Root CA public key
│
└── ITS/
      __init__.py
      Address.py
      certs_util.py
      Cryptico.py
      Entity.py
      Link_Authority.py
      Long_Term_Certificate_Authority.py
      mini_packet.py
      Pseudonym_Certificate_Authority.py
      Registration_Authority.py
      Vehicule.py
```

---

## Main Components

### Entities

- **Registration Authority (RA)**  
  Handles vehicle registration and acts as a bridge between vehicles and certificate authorities.

- **Long-Term Certificate Authority (LTCA)**  
  Issues long-term certificates to vehicles after registration.

- **Pseudonym Certificate Authority (PCA)**  
  Issues short-lived pseudonym certificates to vehicles for privacy. Maintains a mapping of pseudonyms and PLVs (Pseudonym Link Values).

- **Link Authority (LA1, LA2)**  
  Assists in linking pseudonyms to long-term identities for revocation or investigation.

- **Vehicle (Vehicule)**  
  Represents a vehicle in the network. Requests certificates, sends messages, and can simulate malicious behavior.

Each entity is implemented as a class in the [`ITS`](ITS/) package:
- [`ITS.Registration_Authority`](ITS/Registration_Authority.py)
- [`ITS.Long_Term_Certificate_Authority`](ITS/Long_Term_Certificate_Authority.py)
- [`ITS.Pseudonym_Certificate_Authority`](ITS/Pseudonym_Certificate_Authority.py)
- [`ITS.Link_Authority`](ITS/Link_Authority.py)
- [`ITS.Vehicule`](ITS/Vehicule.py)

### Addressing

All entities communicate over localhost using unique port pairs for sending and listening. Address management is handled by the [`ITS.Address`](ITS/Address.py) class.

### Certificate Management

- **Root CA**: Generated with [`generate_root_cert.py`](generate_root_cert.py), stored in [`ca/`](ca/).
- **Certificate Utilities**: Encoding, decoding, and cryptographic operations are provided by [`ITS.certs_util`](ITS/certs_util.py) and [`ITS.Cryptico`](ITS/Cryptico.py).
- **ASN.1 Encoding**: Certificates and messages are encoded using ASN.1 schemas from [`asn/`](asn/).

### Communication

Entities send and receive messages using sockets. The message format and packetization are handled by [`ITS.mini_packet`](ITS/mini_packet.py).

---

## Simulation Workflow

The main simulation logic is in [`__main__.py`](__main__.py):

1. **Address Initialization**  
   Each entity is assigned a unique address (host, port).

2. **Entity Creation**  
   All authorities and vehicles are instantiated.

3. **Entity Linking**  
   Entities are linked using `initArch()` to establish trust relationships.

4. **Service Startup**  
   All entities start their services (threads/processes).

5. **Vehicle Requests**  
   Vehicles send certificate requests to the RA, which coordinates with LTCA and PCA.

6. **Malicious Behavior Simulation**  
   A vehicle can use a pseudonym certificate to simulate malicious activity. The system can detect and revoke the certificate.

7. **Certificate Revocation**  
   Collaboration between PCA and LA enables revocation of compromised pseudonym certificates.

---

## How to Run

1. **Install dependencies:**
   ```sh
   pip install -r requirements.txt
   ```

2. **Generate Root CA (if not already present):**
   ```sh
   python generate_root_cert.py
   ```

3. **Start the simulation:**
   ```sh
   python __main__.py
   ```

   The script will:
   - Initialize all entities
   - Start services
   - Simulate vehicle requests and malicious behavior
   - Print outputs to the console

---

## ASN.1 Schemas

The project uses ASN.1 schemas for certificate and message definitions:
- [`asn/Ieee1609Dot2BaseTypes.asn`](asn/Ieee1609Dot2BaseTypes.asn)
- [`asn/Etsi_flattened.asn`](asn/Etsi_flattened.asn)

These schemas define the structure for certificates, CRLs, and permissions, ensuring interoperability with real-world VPKI systems.

---

## Customization

- **Add More Vehicles:**  
  Instantiate more `Vehicule` objects in [`__main__.py`](__main__.py) with unique ports.

- **Change Entity Behavior:**  
  Modify the respective class in [`ITS/`](ITS/) to change how an entity processes messages or handles certificates.

- **Simulate Different Attacks:**  
  Extend the malicious behavior section in [`__main__.py`](__main__.py) to test different scenarios.

---

## Development Notes

- The code is modular: each entity is a separate class.
- Communication is over localhost sockets for simulation purposes.
- Certificates are encoded using ASN.1 PER format.
- The project is intended for research, education, and prototyping of VPKI systems.

---

## Project File and Folder Overview

### Top-Level Files

- **__main__.py**  
  The main entry point for the simulation. Initializes all entities (RA, LTCA, PCA, LA1, LA2, vehicles), sets up their addresses, starts their services, and simulates vehicle requests and malicious behavior scenarios.

- **generate_root_cert.py**  
  Script to generate the root certificate authority (CA) key pair and certificate, which are used to sign other certificates in the system.

- **README.md**  
  This documentation file. Should provide an overview of the project, its structure, and usage instructions.

- **requirements.txt**  
  Lists all Python dependencies required to run the project.

---

### Folders

#### asn/
Contains ASN.1 schema files used for encoding/decoding certificates and messages according to vehicular communication standards.

- **Etsi_flattened.asn**  
  ASN.1 definitions for ETSI TS 103 097, describing certificate and message formats for European vehicular networks.

- **Ieee1609Dot2BaseTypes.asn**  
  ASN.1 definitions for IEEE 1609.2, describing base types, certificate structures, CRLs, and security envelopes for vehicular communications.

---

#### ca/
Stores cryptographic material for the root certificate authority.

- **root_ca.cert**  
  The root CA certificate (public part).

- **root_ca.key.pem**  
  The root CA private key in PEM format.

- **root_ca.pub.pem**  
  The root CA public key in PEM format.

---

#### ITS/
Main Python package containing all core logic for the simulation. Each file typically defines a class representing an entity or utility in the system.

- **__init__.py**  
  Marks the directory as a Python package.

- **Address.py**  
  Defines the `Address` class, which encapsulates host and port information for entity communication.

- **certs_util.py**  
  Utility functions for certificate creation, encoding/decoding, and cryptographic operations.

- **Cryptico.py**  
  Handles cryptographic primitives and operations (e.g., key generation, encryption, decryption).

- **Entity.py**  
  Base class for all entities (authorities and vehicles) in the system. Provides common methods for communication and state management.

- **Link_Authority.py**  
  Implements the Link Authority (LA) entity, which helps link pseudonyms to long-term identities and assists in certificate revocation.

- **Long_Term_Certificate_Authority.py**  
  Implements the Long-Term Certificate Authority (LTCA), responsible for issuing long-term certificates to vehicles.

- **mini_packet.py**  
  Defines the structure and handling of packets/messages exchanged between entities.

- **Pseudonym_Certificate_Authority.py**  
  Implements the Pseudonym Certificate Authority (PCA), which issues pseudonym certificates to vehicles for privacy.

- **Registration_Authority.py**  
  Implements the Registration Authority (RA), which registers vehicles and coordinates certificate issuance.

- **Vehicule.py**  
  Implements the vehicle entity. Handles certificate requests, stores received certificates, and can simulate malicious behavior.

---

### Summary

- **asn/**: ASN.1 schemas for message/certificate encoding.
- **ca/**: Root CA keys and certificate.
- **ITS/**: All core simulation logic and entity implementations.
- **__main__.py**: Simulation entry point.
- **generate_root_cert.py**: Root CA generation.
- **requirements.txt**: Python dependencies.
- **README.md**: Project documentation.

This structure supports a modular, extensible simulation of a secure vehicular communication system, following real-world standards.

---

## References

- ETSI TS 103 097: Intelligent Transport Systems (ITS); Security; Security header and certificate formats
- IEEE 1609.2: Standard for Wireless Access in Vehicular Environments - Security Services for Applications and Management Messages
