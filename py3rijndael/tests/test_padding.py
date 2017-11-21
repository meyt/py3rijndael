import unittest
from py3rijndael import ZeroPadding, Pkcs7Padding


class PaddingTestCase(unittest.TestCase):

    def test_zero_padding(self):
        padding = ZeroPadding(block_size=16)
        source = b'hi'
        encoded_source = padding.encode(source)
        self.assertEqual(encoded_source, b'hi\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')
        self.assertEqual(len(encoded_source), 16)
        self.assertEqual(padding.decode(encoded_source), source)

        # unpad test
        padding.decode(b'')
        with self.assertRaises(AssertionError):
            padding.decode(b'no-padding')

    def test_pkcs7_padding(self):
        padding = Pkcs7Padding(block_size=16)
        source = b'hi'
        encoded_source = padding.encode(source)
        self.assertEqual(encoded_source, b'hi\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e')
        self.assertEqual(len(encoded_source), 16)
        self.assertEqual(padding.decode(encoded_source), source)


if __name__ == '__main__':  # pragma: nocover
    unittest.main()
