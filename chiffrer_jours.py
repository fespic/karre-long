#!/usr/bin/env python3
"""
Chiffre les journées du tableau de bord Karré Long.

Usage :
    python3 chiffrer_jours.py jours.json "phrase secrète" jours.enc

Le fichier produit est déposé tel quel sur GitHub Pages.
Sans la phrase, il est inexploitable.

Paramètres cryptographiques, identiques côté application :
    PBKDF2-HMAC-SHA256, 250 000 itérations, sel aléatoire de 16 octets
    AES-256-GCM, vecteur d'initialisation aléatoire de 12 octets
"""
import base64
import hashlib
import json
import os
import sys

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

ITER = 250_000


def b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode()


def chiffrer(donnees, phrase: str) -> dict:
    sel = os.urandom(16)
    iv = os.urandom(12)
    cle = hashlib.pbkdf2_hmac("sha256", phrase.encode("utf-8"), sel, ITER, dklen=32)
    clair = json.dumps(donnees, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    chiffre = AESGCM(cle).encrypt(iv, clair, None)
    return {"v": 1, "iter": ITER, "salt": b64(sel), "iv": b64(iv), "data": b64(chiffre)}


def dechiffrer(paquet: dict, phrase: str):
    """Vérification locale, utilisé par les tests."""
    sel = base64.b64decode(paquet["salt"])
    iv = base64.b64decode(paquet["iv"])
    cle = hashlib.pbkdf2_hmac("sha256", phrase.encode("utf-8"), sel,
                              paquet.get("iter", ITER), dklen=32)
    clair = AESGCM(cle).decrypt(iv, base64.b64decode(paquet["data"]), None)
    return json.loads(clair)


def main():
    if len(sys.argv) != 4:
        print(__doc__)
        sys.exit(1)
    entree, phrase, sortie = sys.argv[1], sys.argv[2], sys.argv[3]

    if len(phrase) < 8:
        print("Phrase trop courte : au moins 8 caractères.")
        sys.exit(1)

    with open(entree, encoding="utf-8") as f:
        donnees = json.load(f)

    if not isinstance(donnees, list):
        donnees = [donnees]
    for j in donnees:
        if "date" not in j or "clients" not in j:
            print(f"Journée invalide, il manque 'date' ou 'clients' : {j.get('date', '?')}")
            sys.exit(1)

    paquet = chiffrer(donnees, phrase)

    # relecture de contrôle avant écriture
    assert dechiffrer(paquet, phrase) == donnees, "Le contrôle de déchiffrement a échoué."

    with open(sortie, "w", encoding="utf-8") as f:
        json.dump(paquet, f)

    dates = ", ".join(j["date"] for j in donnees)
    print(f"{len(donnees)} journée(s) chiffrée(s) : {dates}")
    print(f"Écrit dans {sortie} ({os.path.getsize(sortie)} octets)")


if __name__ == "__main__":
    main()
