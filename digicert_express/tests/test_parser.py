__author__ = 'jfischer'

import unittest
import augeas

TEST_ROOT = "/tmp/testroot"


class TestExpressUtils(unittest.TestCase):

    def setUp(self):
        self.test_root = TEST_ROOT
        self.a = augeas.Augeas(root=self.test_root)

    def tearDown(self):
        pass

    def test_augeas_basic_match(self):
        "here just as an example and reference"
        matches = self.a.match("/files/etc/hosts/*")
        print matches
        self.failUnless(matches)
        for i in matches:
            for attr in self.a.match(i+"/*"):
                print attr
                self.failUnless(self.a.get(attr) is not None)
        del self.a


if __name__ == '__main__':
    unittest.main()