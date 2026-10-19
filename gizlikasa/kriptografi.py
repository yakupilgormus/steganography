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

    @classmethod
    def bayttan(cls, blob: bytes) -> "AnahtarZarf":
        if not blob.startswith(b"SVE1"):
            raise ValueError("güvenli kasadan olmayan anahtar zarfı")
        off = 4
        ipucu_len = blob[off]
        off += 1
        ipucu = blob[off:off + ipucu_len].decode("utf-8")
        off += ipucu_len
        tuz = blob[off:off + TUZ_BOYUTU]
        off += TUZ_BOYUTU
        nonce = blob[off:off + NONCE_BOYUTU]
        off += NONCE_BOYUTU
        (sarilma_uzunlugu,) = struct.unpack(">H", blob[off:off + 2])
        off += 2
        sarilmis = blob[off:off + sarilma_uzunlugu]
        if len(sarilmis) != sarilma_uzunlugu:
            raise ValueError("yarım kalmış zarf")
        return cls(tuz=tuz, nonce=nonce, sarilmis=sarilmis, ipucu=ipucu)

def anahtari_sarla(anahtar: bytes, parola: str, ipucu: str = "") -> AnahtarZarf:
    """taşıma aka. depolama için bir parolanın altındaki ham anahtarı şifreleme"""
    if len(anahtar) != ANAHTAR_BUYUKLUK:
        raise ValueError("anahtar 32 byte olmalıdır")
    tuz = os.urandom(TUZ_BOYUTU)
    nonce = os.urandom(NONCE_BOYUTU)
    kaplama_anahtari = turetilmis_kaplama_anahtari(parola, tuz)
    sarilmis = AESGCM(kaplama_anahtari).encrypt(nonce, anahtar, b"güvenlik-kasa-anahatar-zarf-v1")
    return AnahtarZarf(tuz=tuz, nonce=nonce, sarilmis=sarilmis, ipucu=ipucu)

def zarftan_cikar_zarf(zarf: AnahtarZarf, parola: str) -> bytes:
    kaplama_anahtari = turetilmis_kaplama_anahtari(parola, zarf.tuz)
    try:
        return AESGCM(kaplama_anahtari).decrypt(zarf.nonce, zarf.sarilmis, b"güvenlik-kasa-anahatar-zarf-v1")
    except InvalidTag as exc:
        raise DesifrelemeHatasi("yanlış parola veya bozuk anahtar zarfı") from exc

def dilim_nonce(temel_nonce: bytes, indeks: int) -> bytes:
    """
    rastgele dosya nonce'ından türetilen belirlenmeli dilim başına nonce

    temel_nonce 8 rastgele bayt 4-byte büyük-biti sonlu sayaç ekliyoruz
    dosya başına taze rastgele temele sahip olmak dosyalar arasında çakışmaları ihmal edilebilir kılar
    ve dosya içinde her dilime benzersiz bir nonce verilir
    """
    if indeks >= 2**32:
        raise ValueError("bu nonce şeması için dosya çok büyük")
    return temel_nonce + struct.pack(">I", indeks)
