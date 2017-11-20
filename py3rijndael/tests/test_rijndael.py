import unittest
import base64
from py3rijndael import Rijndael


class RijndaelTestCase(unittest.TestCase):

    def test_rijndael(self):
        key = 'qBS8uRhEIBsr8jr8vuY9uUpGFefYRL2HSTtrKhaI1tk='

        rijndael = Rijndael(base64.b64decode(key), block_size=32)
        plain_text = 'Mahdi'
        padded_text = plain_text.ljust(32, b'\x1b'.decode())
        cipher = rijndael.encrypt(padded_text)
        cipher_text = base64.b64encode(cipher)
        self.assertEqual(cipher_text, b'Kc8C3vjf+EpLRmgTZ5ckWTzJ/6n7WBHW8pkByDscI/E=')
        self.assertEqual(rijndael.decrypt(cipher), padded_text)

        plain_text = 'lorem lorem lorem la la la..'
        padded_text = plain_text.ljust(32, b'\x1b'.decode())
        cipher = rijndael.encrypt(padded_text)
        self.assertEqual(rijndael.decrypt(cipher), padded_text)

if __name__ == '__main__':  # pragma: nocover
    unittest.main()
