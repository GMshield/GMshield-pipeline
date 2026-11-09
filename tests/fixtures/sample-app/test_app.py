import unittest

from app import body_for


class BodyTest(unittest.TestCase):
    def test_health(self):
        self.assertEqual(body_for("/health")[0], 200)

    def test_unknown_path(self):
        self.assertEqual(body_for("/nope")[0], 404)


if __name__ == "__main__":
    unittest.main()
