import os
import argparse
import subprocess
import platform
import shutil
import getpass
from httplib import HTTPSConnection
import apt.cache

from parsers.base import BaseParser
from cqrs import LoginCommand
from digicert_client import CertificateOrder, Request

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

DEB_DEPS_64 = ['augeas-lenses', 'augeas-tools', 'libaugeas0', 'python-augeas', 'openssl', 'python-pip']
DEB_DEPS_32 = ['augeas-lenses', 'augeas-tools:i386', 'libaugeas0:i386', 'python-augeas', 'openssl', 'python-pip']

RH_DEPS = ['openssl', 'augeas-libs', 'augeas', 'python-pip']

HOST = 'localhost.digicert.com'


def run():
    parser = argparse.ArgumentParser(description='Express Install. Let DigiCert manage your certificates for you!', version='1.0')

    subparsers = parser.add_subparsers(help='Choose a command')
    parser_a = subparsers.add_parser('restart_apache', help='restart apache')
    parser_a.add_argument("--domain", action="store", nargs="?", help="I'll verify the domain is running after the restart")
    parser_a.set_defaults(func=restart_apache)

    parser_b = subparsers.add_parser('parse_apache', help='Parse apache configuration file')
    parser_b.add_argument("--host", action="store", help="I need a host to update")
    parser_b.add_argument("--cert", action="store", help="I need the path to the cert for the configuration file")
    parser_b.add_argument("--key", action="store", help="I need the path to the key for the configuration file")
    parser_b.add_argument("--chain", action="store", help="I need the cert chain for the configuration file")
    parser_b.add_argument("--apache_config", action="store", default=None,
                          help="If you know the path your Virtual Host file or main Apache configuration file please "
                               "include it here, if not we will try to find it for you")
    parser_b.set_defaults(func=parse_apache)

    parser_c = subparsers.add_parser('dep_check', help="I'll check that you have all needed software and install it for you")
    parser_c.set_defaults(func=check_for_deps)

    parser_e = subparsers.add_parser('download_cert', help='download certificate')
    parser_e.add_argument("--order_id", action="store", help="I need an order_id")
    parser_e.add_argument("--api_key", action="store", nargs="?", help="I need an API Key")
    parser_e.add_argument("--account_id", nargs="?", action="store", help="I need an account_id")
    parser_e.add_argument("--file_path", action="store", default=os.getcwd(), help="File path should I store the cert? File will be named cert.crt")
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

    args.func(args)
    print 'finished!'


def restart_apache(args):
    distro_name = _determine_platform()
    command = APACHE_COMMANDS.get(distro_name)
    print subprocess.call(command, shell=True)
    # TODO: receive domain in args
    if args.domain:
        import time
        print 'waiting for apache process...'
        time.sleep(4)
        # TODO: add check for apache process and check that is ssl methods here
        apache_process_result = _check_for_apache_process(distro_name)
        site_result = _check_for_site_availability(args.domain)
        ssl_result = _check_for_site_openssl(args.domain)

        if not apache_process_result or not site_result or not ssl_result:
            print "An error occurred starting apache.  Please restore your previous configuration file"



def parse_apache(args):
    print "my job is to parse the apache configuration file and store a backup and update the ssl config"
    if args.host and args.cert and args.key and args.chain:
        try:
            apache_parser = BaseParser(args.host, args.cert, args.key, args.chain)
            apache_parser.load_apache_configs(args.apache_config)
            virtual_host = apache_parser.get_vhost_path_by_domain()
            apache_parser.set_certificate_directives(virtual_host)
        except Exception as e:
            print e.message


def get_temp_api_key():
    # prompt for username and password,
    username = raw_input("DigiCert Username: ")
    password = getpass.getpass("DigiCert Password: ")

    # call /key/temp to get a temp key, then cert order
    params = {'username': username, 'password': password}
    headers = {'Content-type': 'application/x-www-form-urlencoded', 'Accept': 'application/json'}
    conn = HTTPSConnection(HOST)
    conn.request('POST', '/services/v2/authentication/login', urllib.urlencode(params), headers)
    response = conn.getresponse()
    if response.status == 200:
        d = json.loads(response.read())
        print d
        api_key = d.get('api_key', '')
        return api_key
    else:
        print 'Unexpected response from server: %s' % response.reason
        return


def download_cert(args):
    print "download cert from digicert.com with order_id %s and account_id %s" % (args.order_id, args.account_id)
    api_key = args.api_key
    account_id = args.account_id

    if not api_key or args.username:
        api_key = get_temp_api_key()

    if api_key:
        # orderclient = CertificateOrder(HOST, api_key, customer_name=account_id)
        orderclient = CertificateOrder(HOST, api_key)
        certificates = orderclient.download(digicert_order_id=args.order_id)
        result_cert = certificates.get('certificates').get('certificate')
        file = open(args.file_path + '/cert.crt', 'w')
        file.write(result_cert)
        print result_cert
    else:
        print 'Username or API Key required to download certificate.'


def get_order_info(args):
    print "my job is to get the order info for the certificate from digicert.com using the digicert_client module " \
          "with order_id %s and account_id %s" % (args.order_id, args.account_id)
    api_key = args.api_key
    order_id = args.order_id

    if not api_key or args.username:
        api_key = get_temp_api_key()

    if api_key:
        # call the V2 view order API
        orderclient = CertificateOrder(HOST, api_key)
        order_info = orderclient.view(digicert_order_id=order_id)
        if order_info:
            print order_info['status']
            if order_info['status'] and order_info['status'] == 'issued':
                certificate = order_info['certificate']
                if certificate:
                    server_name = certificate['common_name']
                    org_info = order_info['organization']

                    if org_info:
                        create_csr(server_name, org_info['name'], org_info['city'], org_info['state'], org_info['country'])
                    else:
                        raise Exception("ERROR: We could not find your organization's information "
                                        "for order #{0}".format(order_id))
                else:
                    raise Exception("ERROR: We could not find a certificate for order #{0}".format(order_id))
            else:
                raise Exception("ERROR: Order #{0} has not been issued.".format(order_id))
        else:
            raise Exception("ERROR: We could not find any information regarding order #{0}.".format(order_id))


def create_csr(server_name, org, city, state, country, key_size=2048):
    # remove http:// and https:// from server_name
    server_name = server_name.lstrip("http://")
    server_name = server_name.lstrip("https://")

    # remove commas from org, state, & country
    org = org.replace(",", "")
    state = state.replace(",", "")
    country = country.replace(",", "")

    subj_string = "/C={0}/ST={1}/L={2}/O={3}/CN={5}".format(country, state, city, org, server_name)
    csr_cmd = 'openssl req -new -newkey rsa:{0} -nodes -out {1}.csr -keyout {2}.key ' \
              '-subj "{3}"'.format(key_size, server_name, server_name, subj_string)

    # run the command
    csr_output = os.popen(csr_cmd).read()

    # verify the existence of the key and csr files
    if not os.path.exists("{0}.key".format(server_name)) or not os.path.exists("{0}.csr".format(server_name)):
        raise Exception("ERROR: An error occurred while attempting to create your CSR file.  Please try running {0} "
                        "manually and re-run this application with the CSR file location "
                        "as part of the arguments.".format(csr_cmd))


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
    # For simply checking that the site is available HTTPSConnection is good enough
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


if __name__ == '__main__':
    run()
