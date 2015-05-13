__author__ = 'jfischer'

import unittest
import express_utils


class TestExpressUtils(unittest.TestCase):
    def test_platform(self):
        self.assertEqual(len(express_utils.determine_platform()), 3)
        self.assertIn(express_utils.determine_platform()[0], express_utils.SUPPORTED_PLATFORMS)

    def test_restart_apache(self):
        self.assertFalse(express_utils.restart_apache())

    def test_check_for_apache_process(self):
        self.assertTrue('FOO'.isupper())
        self.assertFalse('Foo'.isupper())

    def test_create_csr(self):
        csr = express_utils.create_csr('servername.com')
        self.assertIn(csr['key'], csr['key'])
        self.assertEqual(csr['key'], csr['key'])

    def test_check_requirements(self):
        what = express_utils.check_requirements()
        print what
        print len(what)
        print what[0]
        print what[1]
        print what[2]


if __name__ == '__main__':
    unittest.main()