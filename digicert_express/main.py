import os
import argparse
import subprocess
import platform
import shutil
import getpass
from httplib import HTTPSConnection
from fnmatch import fnmatch
import socket
import ssl
import urllib
import apt.cache

from parsers.base import BaseParser
from digicert_client import CertificateOrder

APACHE_COMMANDS = {
    'LinuxMint': 'sudo service apache2 restart',
    'CentOS': 'sudo service httpd restart',
    'Debian': 'sudo /etc/init.d/apache2 restart',
    'Ubuntu': 'sudo service apache2 restart'
}

APACHE_PROCESS_NAMES = {
    'LinuxMint': 'apache2',
    'CentOS': 'httpd',
    'Debian': 'apache2',
    'Ubuntu': 'apache2'
}

DEB_DEPS_64 = ['augeas-lenses', 'augeas-tools', 'libaugeas0', 'python-augeas', 'openssl']
DEB_DEPS_32 = ['augeas-lenses', 'augeas-tools:i386', 'libaugeas0:i386', 'python-augeas', 'openssl']

RH_DEPS = ['openssl', 'augeas-libs', 'augeas', 'python-pip']

HOST = 'localhost.digicert.com'


def run():
    parser = argparse.ArgumentParser(
        description='Express Install. Let DigiCert manage your certificates for you!', version='1.0 First pass')

    subparsers = parser.add_subparsers(help='Choose a command')
    parser_a = subparsers.add_parser('restart_apache', help='restart apache')
    parser_a.set_defaults(func=restart_apache)

    parser_b = subparsers.add_parser('parse_apache', help='parse apache')
    parser_b.add_argument("--host", action="store", help="I need a host to update")
    parser_b.add_argument("--cert", action="store", help="I need the path to the cert for the configuration file")
    parser_b.add_argument("--chain", action="store", help="I need the cert chain for the configuration file")
    parser_b.set_defaults(func=parse_apache)

    parser_c = subparsers.add_parser('dep_check', help="I'll check that you have all needed software and install it for you")
    parser_c.set_defaults(func=check_for_deps)


    parser_e = subparsers.add_parser('download_cert', help='download certificate')
    parser_e.add_argument("--order_id", action="store", help="I need an order_id")
    parser_e.add_argument("--api_key", action="store", nargs="?", help="I need an API Key")
    parser_e.add_argument("--account_id", nargs="?", action="store", help="I need an account_id")
    parser_e.add_argument("--username", action="store_true", help="Your DigiCert username")
    parser_e.add_argument("--file_path", action="store", default=os.getcwd(), help="Where should I store the cert?")
    parser_e.set_defaults(func=download_cert)

    parser_f = subparsers.add_parser('copy_cert', help='activate certificate')
    parser_f.add_argument("--cert_path", action="store", help="Path to the cert")
    parser_f.add_argument("--apache_path", action="store", help="Path to store the cert")
    parser_f.set_defaults(func=copy_cert)

    parser_g = subparsers.add_parser("all", help='Download and Configure cert in one step')
    parser_g.add_argument("--order_id", action="store", help="I need an order_id")
    parser_g.add_argument("--api_key", action="store", help="I need an API Key")
    parser_g.add_argument("--account_id", nargs="?", action="store", help="I need an account_id")
    parser_g.add_argument("--file_path", action="store", default=os.getcwd(), help="Where should I store the cert?")
    parser_g.set_defaults(func=do_everything)

    args = parser.parse_args()
    print args

    # TODO: if download and api key but not key passed in, throw error

    args.func(args)
    print 'finished!'


def restart_apache(args):
    distro_name = _determine_platform()
    command = APACHE_COMMANDS.get(distro_name)
    print subprocess.call(command, shell=True)


def parse_apache(args):
    if args.host and args.cert and args.chain:
        try:
            apache_parser = BaseParser(args.host, args.cert, args.chain)
            apache_parser.load_apache_configs()
            virtual_host = apache_parser.get_vhost_path_by_domain()
            apache_parser.set_certificate_directives(virtual_host)
        except Exception as e:
            print e.message


def download_cert(args):
    print "download cert from digicert.com with order_id %s and account_id %s" % (args.order_id, args.account_id)
    api_key = args.api_key
    account_id = args.account_id
    if args.username:
        # prompt for username and password,
        username = raw_input("DigiCert Username: ")
        password = getpass.getpass("DigiCert Password: ")

        # call /key/temp to get a temp key, then cert order
        params = {'username': username, 'password': password}
        headers = {'Content-type': 'application/x-www-form-urlencoded', 'Accept': 'application/json'}
        conn = HTTPSConnection(HOST)
        conn.request('POST', '/services/v2/key/temp', urllib.urlencode(params), headers)
        response = conn.getresponse()
        print response
        if response.status == 200:
            d = response.read()
        api_key = d.get('api_key', '')

    if api_key:
        orderclient = CertificateOrder(HOST, api_key, customer_name=account_id)
        certificates = orderclient.download(digicert_order_id=args.order_id)
        result_cert = certificates.get('certificates').get('certificate')
        file = open(args.file_path + '/cert.crt', 'w')
        file.write(result_cert)

    print result_cert


def copy_cert(args):
    cert_path = args.cert_path
    apache_path = args.apache_path
    shutil.copyfile(cert_path, apache_path)


def do_everything(args):
    download_cert(args)
    parse_apache(args)
    copy_cert(args)
    restart_apache(args)


def _determine_platform():
    distro_name = platform.linux_distribution()  # returns a tuple ('', '', '') (distroName, version, code name)
    return distro_name[0]


def _check_for_apache_process(platform_name):
    process_name = APACHE_PROCESS_NAMES.get(platform_name)
    process = os.popen("ps aux | grep %s" % process_name).read().splitlines()
    if len(process) > 2:
        return True
    else:
        return False


def _check_for_site_availability(domain):
    conn = HTTPSConnection('localhost.digicert.com')
    conn.request('GET', '/')
    response = conn.getresponse()
    print response
    site_status = False
    if response.status == 200:
        site_status = True

    return site_status


def _check_for_site_openssl(domain):
    # openssl s_client -connect jboards.net:443
    process = os.popen("openssl s_client -connect %s:443 %s" % domain).read().splitlines()
    site_status = False
    if 'CONNECTED' in process:
        site_status = True
    return site_status


def check_for_deps(args):
    distro = platform.linux_distribution()
    if distro == 'CentOS':
        check_for_deps_centos()
    else:
        check_for_deps_debian()


def check_for_deps_debian():
    # check to see which of the deps are install
    try:
        a = apt.cache.Cache(memonly=True)

        for d in DEB_DEPS_64:
            if a[d].is_installed:
                continue
            else:
                # prompt for install
                answer = raw_input('Install: %s (y/n) ' % a[d].name)
                if answer.lower() == 'y':
                    a[d].mark_install()
                    # TODO add else for n condition
        a.commit()
    except ImportError:
        pass


def check_for_deps_centos():
    try:
        import yum
        yb = yum.YumBase()
        packages = yb.rpmdb.returnPackages()
        for p in packages:
            for package_name in RH_DEPS:
                if package_name in [x.name for x in packages]:
                    continue
                else:
                    answer = raw_input('Install: %s (y/n) ' % p.name)
                    if answer.lower().strip() == 'y':
                        yb.install(name=p.name)
                    else:
                        print "Please install package yourself: %s" % package_name
                        raw_input("Press enter to continue: ")
    except ImportError:
        pass


def _check_for_site_openssl(domain):
    # openssl s_client -connect jboards.net:443
    process = os.popen("openssl s_client -connect %s:443 -showcerts < /dev/null" % domain).read()
    print process
    site_status = False
    if 'CONNECTED' in process:
        site_status = True
    return site_status


class VerifiedHTTPSConnection(HTTPSConnection):
    """
    VerifiedHTTPSConnection - an HTTPSConnection that performs name and server cert verification
    when a connection is created.
    """

    # This code is based very closely on https://gist.github.com/Caligatio/3399114.

    ca_file = None

    def __init__(self,
                 host,
                 port=None,
                 ca_file=None,
                 **kwargs):
        HTTPSConnection.__init__(self,
                                 host=host,
                                 port=port,
                                 **kwargs)

        if ca_file:
            self.ca_file = ca_file
        else:
            self.ca_file = os.path.join(os.path.dirname(__file__), 'DigiCertRoots.pem')

    def connect(self):
        if self.ca_file and os.path.exists(self.ca_file):
            sock = socket.create_connection(
                (self.host, self.port),
                self.timeout, self.source_address
            )

            if self._tunnel_host:
                self.sock = sock
                self._tunnel()

            # Wrap the socket using verification with the root certs, note the hardcoded path
            self.sock = ssl.wrap_socket(sock,
                                        self.key_file,
                                        self.cert_file,
                                        cert_reqs=ssl.CERT_REQUIRED,
                                        ca_certs=self.ca_file)
            verify_peer(self.host, self.sock.getpeercert())
        else:
            raise RuntimeError('No CA file configured for VerifiedHTTPSConnection')


def verify_peer(remote_host, peer_certificate):
    """
    check_hostname()

    Checks the hostname being accessed against the various hostnames present
    in the remote certificate
    """
    hostnames = set()
    wildcard_hostnames = set()

    for subject in peer_certificate['subject']:
        if 'commonName' == subject[0] and len(subject) > 1:
            hostname = subject[1].encode('utf-8')
            wch_tuple = tuple(hostname.split('.'))
            if -1 != wch_tuple[0].find('*'):
                wildcard_hostnames.add(wch_tuple)
            else:
                hostnames.add(hostname)

    # Get the subject alternative names out of the certificate
    try:
        sans = (x for x in peer_certificate['subjectAltName'] if x[0] == 'DNS')
        for san in sans:
            if len(san) > 1:
                wch_tuple = tuple(san[1].split('.'))
                if -1 != wch_tuple[0].find('*'):
                    wildcard_hostnames.add(wch_tuple)
                else:
                    hostnames.add(san[1])
    except KeyError:
        pass

    if remote_host not in hostnames:
        wildcard_match = False
        rh_tuple = tuple(remote_host.split('.'))
        for wch_tuple in wildcard_hostnames:
            l = len(wch_tuple)
            if len(rh_tuple) == l:
                l -= 1
                rhparts_match = True
                while l < 0:
                    if rh_tuple[l] != wch_tuple[l]:
                        rhparts_match = False
                        break
                if rhparts_match and fnmatch(rh_tuple[0], wch_tuple[0]):
                    wildcard_match = True
        if not wildcard_match:
            raise ssl.SSLError('hostname "%s" doesn\'t match certificate name(s) "%s"' %
                               (remote_host, ', '.join(hostnames)))




if __name__ == '__main__':
    run()