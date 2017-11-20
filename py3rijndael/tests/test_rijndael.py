import unittest
import base64
from py3rijndael import Rijndael


class RijndaelTestCase(unittest.TestCase):

    def test_rijndael(self):
        key = 'qBS8uRhEIBsr8jr8vuY9uUpGFefYRL2HSTtrKhaI1tk='

        rijndael = Rijndael(base64.b64decode(key), block_size=32)
        plain_text = b'Mahdi'
        padded_text = plain_text.ljust(32, b'\x1b')
        cipher = rijndael.encrypt(padded_text)
        cipher_text = base64.b64encode(cipher)
        self.assertEqual(cipher_text, b'Kc8C3vjf+EpLRmgTZ5ckWTzJ/6n7WBHW8pkByDscI/E=')
        self.assertEqual(rijndael.decrypt(cipher), padded_text)

        # Block size
        for block_size in (16, 24, 32):
            rijndael2 = Rijndael(base64.b64decode(key), block_size=block_size)
            plain_text = 'lorem'
            padded_text = plain_text.ljust(block_size, b'\x1b'.decode())
            cipher = rijndael2.encrypt(padded_text)
            self.assertEqual(rijndael2.decrypt(cipher), padded_text.encode())

        # Exceptions
        with self.assertRaises(ValueError):
            plain_text = 'Hey' * 20
            padded_text = plain_text.ljust(32, b'\x1b'.decode())
            rijndael.encrypt(padded_text)

        with self.assertRaises(ValueError):
            Rijndael(base64.b64decode(key), block_size=62)

        with self.assertRaises(ValueError):
            Rijndael(base64.b64decode(key) * 20, block_size=32)

        with self.assertRaises(ValueError):
            plain_text = 'Hey'
            padded_text = plain_text.ljust(32, b'\x1b'.decode())
            cipher = rijndael.encrypt(padded_text)
            rijndael.decrypt(cipher * 12)

if __name__ == '__main__':  # pragma: nocover
    unittest.main()
