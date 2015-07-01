__author__ = 'jfischer'

import unittest
import express_utils
import subprocess
import os

class TestExpressUtils(unittest.TestCase):
    def test_platform(self):
        self.assertEqual(len(express_utils.determine_platform()), 3)
        self.assertIn(express_utils.determine_platform()[0], express_utils.SUPPORTED_PLATFORMS)

    def test_restart_apache(self):
        self.assertFalse(express_utils.restart_apache())

    def test_determine_python_version(self):
        self.assertIsNotNone(express_utils.determine_python_version())

    def test_determine_apache_version(self):
        distro = express_utils.determine_platform()
        apache_version = express_utils.determine_apache_version(distro[0])
        self.assertIsNotNone(apache_version)

    def test_check_for_apache_process(self):
        distro = express_utils.determine_platform()
        self.assertTrue(express_utils.check_for_apache_process(distro[0]))

    def test_create_csr(self):
        csr = express_utils.create_csr('servername.com')
        self.assertIn(csr['key'], csr['key'])
        self.assertEqual(csr['key'], csr['key'])

    def test_check_for_deps_debian(self):
        packages_installed = express_utils.check_for_deps_debian(install_prompt=False)
        print packages_installed
        self.assertListEqual(packages_installed, [], msg="Package pre-reqs are not met")

    def test_check_for_site_availability(self):
        status = express_utils.check_for_site_availability('www.digicert.com')
        self.assertTrue(status)

    def test_subprocess(self):
        command = 'sudo service apache2 restart'
        # print subprocess.call(command, shell=True)
        os.system(command)


if __name__ == '__main__':
    unittest.main()