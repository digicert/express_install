import subprocess
import os
import sys
import re
import shutil
from httplib import HTTPSConnection
import platform

from loggers.express_install_logger import ExpressInstallLogger

"""
Module contains utility functions and constants
"""

APACHE_COMMANDS = {
    'LinuxMint': 'service apache2 restart',
    'CentOS': 'service httpd restart',
    'Debian': '/etc/init.d/apache2 restart',
    'Ubuntu': 'service apache2 restart'
}

APACHE_PROCESS_NAMES = {
    'LinuxMint': 'apache2',
    'CentOS': 'httpd',
    'Debian': 'apache2',
    'Ubuntu': 'apache2'
}

APACHE_SERVICES = {
    'LinuxMint': 'apache2ctl',
    'CentOS': 'httpd',
    'Debian': 'apache2ctl',
    'Ubuntu': 'apache2ctl'
}

HOST = 'localhost.digicert.com'
DEBIAN_DEPS = ['augeas-lenses', 'augeas-tools', 'libaugeas0', 'openssl', 'python-pip']
CENTOS_DEPS = ['openssl', 'augeas-libs', 'augeas', 'mod_ssl']

CFG_PATH = '/etc/digicert'
LOGFILE = 'digicert_express_config.log'
LOGGER = ExpressInstallLogger(file_name=LOGFILE).get_logger()

SUPPORTED_PLATFORMS = ['Ubuntu', 'CentOS', 'Debian', '10.10.3']


def restart_apache(domain=''):
    LOGGER.info("Restarting your apache server")

    distro_name = determine_platform()
    LOGGER.info("distro name: %s" % distro_name[0])
    command = APACHE_COMMANDS.get(distro_name[0])
    LOGGER.info("apache command: %s" % command)
    subprocess.call(command, shell=True)

    have_error = False
    apache_process_result = check_for_apache_process(distro_name[0])

    if not apache_process_result:
        LOGGER.error("ERROR: Apache did not restart successfully.")
        have_error = True

    if not have_error:
        LOGGER.info('Apache restarted successfully.')
        print ''

    restart_successful = not have_error
    return restart_successful


def validate_key(key, cert):
    key_command = "openssl rsa -noout -modulus -in \"{0}\" | openssl md5".format(key)
    crt_command = "openssl x509 -noout -modulus -in \"{0}\" | openssl md5".format(cert)

    # TODO: is this the best way to call to the CLI
    key_modulus = os.popen(key_command).read()
    crt_modulus = os.popen(crt_command).read()

    return key_modulus == crt_modulus


def copy_cert(cert_path, apache_path):
    shutil.copyfile(cert_path, apache_path)


def enable_ssl_mod():
    LOGGER.info('Enabling Apache SSL module...')
    if determine_platform()[0] != 'CentOS' and not is_ssl_mod_enabled('apache2ctl'):
        try:
            subprocess.check_call(["sudo", 'a2enmod', 'ssl'], stdout=open("/dev/null", 'w'),
                                  stderr=open("/dev/null", 'w'), shell=True)
        except (OSError, subprocess.CalledProcessError) as err:
            raise Exception(
                "There was a problem enabling mod_ssl.  Run 'sudo a2enmod ssl' to enable it or check the apache log for more information")


def is_ssl_mod_enabled(apache_ctl):
    try:
        proc = subprocess.Popen([apache_ctl, '-M'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = proc.communicate()
    except:
        raise Exception("There was a problem accessing 'apachectl'")

    if 'ssl' in stdout:
        return True
    return False


def determine_platform():
    distro_name = platform.linux_distribution()  # returns a tuple ('', '', '') (distroName, version, code name)
    LOGGER.info("Found platform: %s", " : ".join(distro_name))
    return distro_name


def determine_python_version():
    LOGGER.info("Found Python version: %s.%s.%s" % (sys.version_info.major, sys.version_info.minor, sys.version_info.micro))
    return '%s.%s.%s' % (sys.version_info.major, sys.version_info.minor, sys.version_info.micro)


def determine_apache_version(os_name):
    # TODO: is this the best way to call to the CLI
    apache = os.popen("`which %s` -v | grep version" % APACHE_PROCESS_NAMES.get(os_name)).read()
    version_matches = re.findall(r"([0-9.]*[0-9]+)", apache)
    if version_matches:
        LOGGER.info("Found Apache version %s: " % "".join(version_matches))
        return version_matches[0]
    else:
        return ''


def determine_versions():
    os_name, os_version, code_name = determine_platform()
    python_version = determine_python_version()
    apache_version = determine_apache_version(os_name)

    return {'os_name': os_name, 'os_version': os_version, 'code_name': code_name,
            'python_version': python_version, 'apache_version': apache_version}


def check_for_apache_process(platform_name):
    try:
        process_name = APACHE_PROCESS_NAMES.get(platform_name)
        process = os.popen("ps aux | grep %s" % process_name).read().splitlines()
        if len(process) > 2:
            return True
    except Exception, e:
        LOGGER.error("ERROR: %s" % e.message)
    return False


def check_for_site_availability(domain):
    # For simply checking that the site is available HTTPSConnection is good enough
    LOGGER.info("Verifying {0} is available over HTTPS...".format(domain))
    try:
        conn = HTTPSConnection(domain)
        conn.request('GET', '/')
        response = conn.getresponse()
        site_status = (response.status == 200)
        if site_status:
            LOGGER.info("{0} is reachable over HTTPS".format(domain))
        return site_status
    except Exception, e:
        pass
    return False


def check_for_site_openssl(domain):
    LOGGER.info("Validating the SSL configuration for {0}...".format(domain))
    try:
        process = os.popen("timeout 3 openssl s_client -connect %s:443 2>&1" % domain).read().splitlines()
        site_status = False
        if isinstance(process, basestring):
            site_status = 'CONNECTED' in process
        else:
            for line in process:
                if 'CONNECTED' in line:
                    site_status = True
                    break
        if site_status:
            LOGGER.info("SSL configuration for {0} is valid".format(domain))
        return site_status
    except Exception, e:
        LOGGER.error("ERROR: %s" % e.message)
    return False


def check_for_deps_ubuntu(install_prompt=True):
    # check to see which of the deps are installed
    try:
        LOGGER.info("Checking for installed Ubuntu dependencies")
        import apt

        a = apt.cache.Cache(memonly=True)

        newly_installed = []
        for d in DEBIAN_DEPS:
            if a[d].is_installed:
                continue
            else:
                if install_prompt:
                    if raw_input('Install: %s (Y/n) ' % a[d].name).lower().strip() == 'n':
                        LOGGER.info("Please install %s package yourself: " % a[d].name)
                        raw_input("Press enter to continue: ")
                    else:
                        LOGGER.info("Installing %s..." % a[d].name)

                        os.system('apt-get -y install %s &>> %s' % (a[d].name, LOGFILE))
                newly_installed.append(d)

        if not newly_installed:
            LOGGER.info("All package dependencies are installed")
        return newly_installed
    except ImportError:
        pass


def check_for_deps_centos():
    """
    :return:
    """
    try:
        LOGGER.info("Checking for installed CentOS dependencies")
        import yum

        yb = yum.YumBase()
        packages = yb.rpmdb.returnPackages()
        newly_installed = []
        for package_name in CENTOS_DEPS:
            if package_name in [x.name for x in packages]:
                continue
            else:
                if raw_input('Install: %s (Y/n) ' % package_name).lower().strip() == 'n':
                    LOGGER.info("Please install %s package yourself: " % package_name)
                    raw_input("Press enter to continue: ")
                else:
                    LOGGER.info("Installing %s..." % package_name)
                    newly_installed.append(package_name)

                    os.system('yum -y install %s &>> %s' % (package_name, LOGFILE))
        if not newly_installed:
            LOGGER.info("All package dependencies are installed")
        return newly_installed
    except ImportError:
        pass


def create_csr(server_name, org="", city="", state="", country="", key_size=2048):
    """
    Uses this data to create a CSR via OpenSSL
    :param server_name:
    :param org:
    :param city:
    :param state:
    :param country:
    :param key_size:
    :return:
    """
    LOGGER.info("Creating CSR file for {0}...".format(server_name))
    # remove http:// and https:// from server_name
    server_name = server_name.replace("http://", "")
    server_name = server_name.replace("https://", "")

    key_file_name = "{0}.key".format(server_name.replace('.', '_').replace('*', 'star'))
    csr_file_name = "{0}.csr".format(server_name.replace('.', '_').replace('*', 'star'))

    # remove commas from org, state, & country
    org = org.replace(",", "")
    state = state.replace(",", "")
    country = country.replace(",", "")

    subj_string = "/C={0}/ST={1}/L={2}/O={3}/CN={4}".format(country, state, city, org, server_name)
    csr_cmd = 'openssl req -new -newkey rsa:{0} -nodes -out {1} -keyout {2} ' \
              '-subj "{3}" 2>/dev/null'.format(key_size, csr_file_name, key_file_name, subj_string)

    # run the command
    os.system(csr_cmd)

    # verify the existence of the key and csr files
    if not os.path.exists(key_file_name) or not os.path.exists(csr_file_name):
        raise Exception("ERROR: An error occurred while attempting to create your CSR file.  Please try running {0} "
                        "manually and re-run this application with the CSR file location "
                        "as part of the arguments.".format(csr_cmd))
    LOGGER.info("Created private key file {0}...".format(key_file_name))
    LOGGER.info("Created CSR file {0}...".format(csr_file_name))
    print ""
    return key_file_name, csr_file_name


def replace_chars(word, replace_char='.', new_char='_'):
    """
    :param word: word to replace chars
    :param replace_char: what to replace
    :param new_char: what to replace with
    :return: newly replaced word
    """
    temp_word = word.replace(replace_char, new_char)
    return temp_word.replace('*', 'star')
