# -*- coding: utf-8 -*-
"""
Utilities to make secret box encryption simple
"""
# Import libnacl
import libnacl
import libnacl.utils
import libnacl.base


class SecretBox(libnacl.base.BaseKey):
    """
    Manage symmetric encryption using the salsa20 algorithm
    """
    def __init__(self, key=None):
        if not key:
            key = libnacl.utils.salsa_key()
        if len(key) != libnacl.crypto_secretbox_KEYBYTES:
            raise ValueError('Invalid key')
        self.sk = key

    def encrypt(self, msg, nonce=None, pack_nonce=True):
        """
        Encrypt the given message. If a nonce is not given it will be
        generated via the rand_nonce function
        """
        if not nonce:
            nonce = libnacl.utils.rand_nonce()
        if len(nonce) != libnacl.crypto_secretbox_NONCEBYTES:
            raise ValueError('Invalid nonce size')
        ctxt = libnacl.crypto_secretbox(msg, nonce, self.sk)
        if pack_nonce:
            return nonce + ctxt
        else:
            return nonce, ctxt

    def decrypt(self, ctxt, nonce=None):
        """
        Decrypt the given message, if no nonce is given the nonce will be
        extracted from the message
        """
        if not nonce:
            nonce = ctxt[:libnacl.crypto_secretbox_NONCEBYTES]
            ctxt = ctxt[libnacl.crypto_secretbox_NONCEBYTES:]
        if len(nonce) != libnacl.crypto_secretbox_NONCEBYTES:
            raise ValueError('Invalid nonce')
        return libnacl.crypto_secretbox_open(ctxt, nonce, self.sk)
