import unittest

from dragoneye.utils.misc_utils import snakecase


class TestMisUtils(unittest.TestCase):
    def test_snakecase(self):
        # Arrange
        text = 'a-String-WITH-DasH'

        # Act
        snakecase_text = snakecase(text)

        # Assert
        self.assertEqual(snakecase_text, 'a_String_WITH_DasH')
