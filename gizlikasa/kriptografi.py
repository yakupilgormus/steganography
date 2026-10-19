"anahtar yönetimi ve dilimli kimlik doğrulamalı şifreleme"

from __future__ import annotations
import os
import struct
from dataclasses import dataclass
from argon2.low_level import Type, hash_secret_raw
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

ANAHTAR_BUYUKLUGU = 32 # aes-256
NONCE_BOYUTU = 12
TUZ_BOYUTU = 16
DILIM_BOYUTU = 1024 * 1024

ARGON2_ZAMAN_MALIET = 3
ARGON2_HAFIZA_KIB = 262_144
ARGON2_PARALELLIK = 4

