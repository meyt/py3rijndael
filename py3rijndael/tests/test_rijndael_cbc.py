import unittest
import base64
from py3rijndael import RijndaelCbc, ZeroPadding


class RijndaelCbcTestCase(unittest.TestCase):

    def test_rijndael_cbc(self):
        key = 'qBS8uRhEIBsr8jr8vuY9uUpGFefYRL2HSTtrKhaI1tk='
        iv = 'kByhT6PjYHzJzZfXvb8Aw5URMbQnk6NM+g3IV5siWD4='
        rijndael_cbc = RijndaelCbc(
            key=base64.b64decode(key),
            iv=base64.b64decode(iv),
            padding=ZeroPadding(32),
            block_size=32
        )
        plain_text = b'Mahdi'
        padded_text = plain_text.ljust(32, b'\x1b')
        cipher = rijndael_cbc.encrypt(padded_text)
        cipher_text = base64.b64encode(cipher)
        self.assertEqual(cipher_text, b'1KGc0PMt52Xbell+2y9qDJJp/Yy6b1JR1JWI3f9ALF4=')
        self.assertEqual(rijndael_cbc.decrypt(cipher), padded_text)

        # Long blocks
        plain_text = b'lorem' * 50
        padded_text = plain_text.ljust(32, b'\x1b')
        cipher = rijndael_cbc.encrypt(padded_text)
        self.assertEqual(rijndael_cbc.decrypt(cipher), padded_text)


if __name__ == '__main__':  # pragma: nocover
    unittest.main()
