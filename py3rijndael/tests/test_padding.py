import unittest
from py3rijndael import ZeroPadding, Pkcs7Padding


class PaddingTestCase(unittest.TestCase):

    def test_zero_padding(self):
        padding = ZeroPadding(block_size=16)

        # Full length
        source = b'loremipsumdolors'
        encoded_source = padding.encode(source)
        self.assertEqual(encoded_source, source)
        self.assertEqual(len(encoded_source), 16)
        self.assertEqual(padding.decode(encoded_source), source)

        # Length 2
        source = b'hi'
        encoded_source = padding.encode(source)
        self.assertEqual(encoded_source, source + b'\x00' * 14)
        self.assertEqual(len(encoded_source), 16)
        self.assertEqual(padding.decode(encoded_source), source)

        # Length 1
        source = b'h'
        encoded_source = padding.encode(source)
        self.assertEqual(encoded_source, source + b'\x00' * 15)
        self.assertEqual(len(encoded_source), 16)
        self.assertEqual(padding.decode(encoded_source), source)

        # Zero length
        self.assertEqual(padding.decode(b''), b'')

        # Wrong value to decode
        with self.assertRaises(AssertionError):
            padding.decode(b'no-padding')

    def test_pkcs7_padding(self):
        padding = Pkcs7Padding(block_size=16)

        source = b'hi'
        encoded_source = padding.encode(source)
        self.assertEqual(encoded_source, source + b'\x0e' * 14)
        self.assertEqual(len(encoded_source), 16)
        self.assertEqual(padding.decode(encoded_source), source)

        # Empty string
        source = b''
        encoded_source = padding.encode(source)
        self.assertEqual(encoded_source, b'\x10' * 16)
        self.assertEqual(padding.decode(encoded_source), source)

        # String that is longer than a single block
        source = b'this string is long enough to span blocks'
        encoded_source = padding.encode(source)
        self.assertEqual(encoded_source, source + b'\x07' * 7)
        self.assertEqual(len(encoded_source), 48)
        self.assertEqual(len(encoded_source) % 16, 0)
        self.assertEqual(padding.decode(encoded_source), source)

        # Using the max block size
        padding = Pkcs7Padding(block_size=255)
        source = b'hi'
        encoded_source = padding.encode(source)
        self.assertEqual(len(encoded_source.decode()), 255)

if __name__ == '__main__':  # pragma: nocover
    unittest.main()
