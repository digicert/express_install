__author__ = 'jfischer'

import unittest
import augeas
import parsers

TEST_ROOT = "/tmp/testroot"


class TestExpressUtils(unittest.TestCase):

    def setUp(self):
        self.test_root = TEST_ROOT
        self.a = augeas.Augeas(root=self.test_root)
        self.server_name = 'www.test.fr'
        self.san = '*.test.de, *.test.fr'

    def tearDown(self):
        pass

    def test_augeas_basic_match(self):
        """here just as an example and reference for augeas"""

        matches = self.a.match("/files/etc/hosts/*")
        print matches
        self.failUnless(matches)
        for i in matches:
            for attr in self.a.match(i+"/*"):
                print attr
                self.failUnless(self.a.get(attr) is not None)
        del self.a

    def test_server_name_san_match(self):
        result = parsers.compare_match([self.server_name], [self.san])
        self.assertTrue(result)

    def test_server_name_san_match_all_pass(self):
        count = 0
        for test in true_tests:
            result = parsers.compare_match([test.get('server_name')], [test.get('san')])
            count += 1
            self.assertTrue(test.get('result'))
        print "%d domains passed" % count
        self.assertEqual(count, 15)

    def test_server_name_san_match_all_false(self):
        count = 0
        for test in false_tests:
            result = parsers.compare_match([test.get('server_name')], [test.get('san')])
            count += 1
            self.assertFalse(test.get('result'))
        print "%d domains didn't match" % count
        self.assertEqual(count, 15)


if __name__ == '__main__':
    unittest.main()


true_tests = [
    {'server_name': 'foo.com', 'san': 'foo.com', 'result': True},
    {'server_name': 'f', 'san': 'f', 'result': True},
    {'server_name': 'bar.foo.com', 'san': '*.foo.com', 'result': True},
    {'server_name': 'www.test.fr', 'san': '*.test.de, *.test.fr', 'result': True},
    {'server_name': 'wwW.tESt.fr', 'san': '*.test.FR', 'result': True},
    {'server_name': 'xn--poema-9qae5a.com.br', 'san': '*.com.br', 'result': True},
    {'server_name': 'foo.example.com', 'san': '*.example.com', 'result': True},
    {'server_name': 'bar.foo.example.com', 'san': '*.foo.example.com', 'result': True},
    {'server_name': 'baz.bar.foo.example.com', 'san': '*.bar.foo.example.com', 'result': True},
    {'server_name': 'qux.baz.bar.foo.example.com', 'san': '*.baz.bar.foo.example.com', 'result': True},
    {'server_name': 'quux.qux.baz.bar.foo.example.com', 'san': '*.qux.baz.bar.foo.example.com', 'result': True},
    {'server_name': 'h.co.uk', 'san': '*.co.uk', 'result': True},
    {'server_name': '127.0.0.1', 'san': '127.0.0.1', 'result': True},
    {'server_name': '192.168.1.1', 'san': '192.168.1.1', 'result': True},
    {'server_name': 'FEDC:BA98:7654:3210:FEDC:ba98:7654:3210', 'san': 'FEDC:BA98:7654:3210:FEDC:ba98:7654:3210', 'result': True}
]

false_tests = [
    {'server_name': 'h', 'san': 'i', 'result': False},
    {'server_name': 'f.uk', 'san': 't.uk', 'result': False},
    {'server_name': 'w.bar.foo.com', 'san': 'ww.bar.foo.com', 'result': False},
    {'server_name': 'www.foo.com', 'san': 'www.foo.com#', 'result': False},
    {'server_name': 'www.house.example', 'san': 'ww.house.example', 'result': False},
    {'server_name': 'test.org', 'san': '*.test.org ', 'result': False},
    {'server_name': 'xn--poema-9qae5a.com.br', 'san': '*.xn--poema-9qae5a.com.br', 'result': False},
    {'server_name': 'bar.foo.example.com', 'san': '*.example.com', 'result': False},
    {'server_name': 'baz.bar.foo.example.com', 'san': '*.foo.example.com', 'result': False},
    {'server_name': 'qux.baz.bar.foo.example.com', 'san': '*.bar.foo.example.com', 'result': False},
    {'server_name': 'quux.qux.baz.bar.foo.example.com', 'san': '*.baz.bar.foo.example.com', 'result': False},
    {'server_name': 'quux.qux.baz.bar.foo.example.com', 'san': '*.example.com', 'result': False},
    {'server_name': 'example.com', 'san': '*.example.com', 'result': False},
    {'server_name': '192.169.1.1', 'san': '192.168.1.1', 'result': False},
    {'server_name': 'FEDC:BA98:7654:3210:FEDC:ba98:7654:3210', 'san': 'FEDC:ba98:7654:3210:FEDC:BA98:7654:3210', 'result': False}
]