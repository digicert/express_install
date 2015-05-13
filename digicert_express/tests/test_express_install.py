__author__ = 'jfischer'

import unittest
import express_install


class TestExpressClient(unittest.TestCase):
    def test_verify_requirements(self):
        express_install.verify_requirements()



if __name__ == '__main__':
    unittest.main()