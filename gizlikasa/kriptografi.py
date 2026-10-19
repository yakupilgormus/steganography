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

class DesifrelemeHatasi(Exception):
    """kimlik doğrulama başarısız olduğunda önemsenmez yanlış anahtar veya bozulmuş veri olarak görülür"""

def anahtar_olustur() -> bytes:
    """kriptografik rastgele aes256 anahtarı"""
    return AESGCM.generate_key(bit_length=256)

def turetilmis_kaplama_anahtari(parola: str, tuz: bytes) -> bytes:
    if len(tuz) != TUZ_BOYUTU:
        raise ValueError("kötü tuz uzunluğu")
    return hash_secret_raw(
        secret=parola.encode("utf-8"),
        salt=tuz,
        time_cost=ARGON2_ZAMAN_MALIET,
        memory_cost=ARGON2_HAFIZA_KIB,
        parallelism=ARGON2_PARALELLIK,
        hash_len=ANAHTAR_BUYUKLUK,
        type=Type.ID,
    )

@dataclass(frozen=True)
class AnahtarZarf:
    """parola ile korunan bir aes anahtarı, taşıyabilir medyada saklanmaya uygundur"""
    tuz: bytes
    nonce: bytes
    sarilmis: bytes
    ipucu: str = ""

    def byteye_cevir(self) -> bytes:
        h = self.ipucu.encode("utf-8")[:255]
        return (
            b"SVE1"
            + struct.pack(">B", len(h))
            + h
            + self.tuz
            + self.nonce
            + struct.pack(">H", len(self.sarilmis))
            + self.sarilmis
        )
