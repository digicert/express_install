import os
import argparse
import subprocess
import platform
import shutil
import getpass
from httplib import HTTPSConnection
import apt.cache
import time

from zipfile import ZipFile
from StringIO import StringIO

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

RH_DEPS = ['openssl', 'augeas-libs', 'augeas', 'python-pip', 'mod_ssl']

HOST = 'localhost.digicert.com'

API_KEY = None


def run():
    parser = argparse.ArgumentParser(description='Express Install. Let DigiCert manage your certificates for you!',
                                     version='1.0')

    subparsers = parser.add_subparsers(help='Choose a command')
    parser_a = subparsers.add_parser('restart_apache', help='Restart apache and verify SSL configuration')
    parser_a.add_argument("--domain", action="store", nargs="?",
                          help="I'll verify the domain is running after the restart")
    parser_a.set_defaults(func=restart_apache)

    parser_b = subparsers.add_parser('parse_apache', help='Parse and update apache configuration with SSL settings')
    parser_b.add_argument("--domain", action="store", help="I need a domain/host to update")
    parser_b.add_argument("--cert", action="store", help="I need the path to the certificate")
    parser_b.add_argument("--key", action="store", help="I need the path to the key")
    parser_b.add_argument("--chain", action="store",
                          help="I need the path to the certificate chain (intermediate)")
    parser_b.add_argument("--apache_config", action="store", default=None,
                          help="If you know the path your Virtual Host file or main Apache configuration file please "
                               "include it here, if not we will try to find it for you")
    parser_b.set_defaults(func=parse_apache)

    parser_c = subparsers.add_parser('dep_check',
                                     help="I'll check that you have all needed software and install it for you")
    parser_c.set_defaults(func=check_for_deps)

    parser_e = subparsers.add_parser('download_cert', help='Download certificate files from DigiCert')
    parser_e.add_argument("--order_id", action="store", help="I need an order_id")
    parser_e.add_argument("--domain", action="store", help="Domain name for the certificate")
    parser_e.add_argument("--api_key", action="store", nargs="?", help="I need an API Key")
    parser_e.add_argument("--file_path", action="store", default="/etc/digicert",
                          help="Where should I store the certificate files? (default: /etc/digicert")
    parser_e.set_defaults(func=download_cert)

    parser_f = subparsers.add_parser('copy_cert', help='Activate certificate')
    parser_f.add_argument("--cert_path", action="store", help="Path to the cert")
    parser_f.add_argument("--apache_path", action="store", help="Path to store the cert")
    parser_f.set_defaults(func=copy_cert)

    parser_g = subparsers.add_parser("all", help='Download and Configure your certificate in one step')
    parser_g.add_argument("--domain", action="store", help="I need a domain to secure")
    parser_g.add_argument("--key", action="store",
                          help="I need the path to the key file (if you already have submitted the csr for your order)")
    parser_g.add_argument("--file_path", action="store", default="/etc/digicert",
                          help="Where should I store the certificate files? (default: /etc/digicert")
    parser_g.add_argument("--api_key", action="store", help="I need an API Key")
    parser_g.add_argument("--order_id", action="store", help="I need an order_id")
    parser_g.set_defaults(func=do_everything)

    args = parser.parse_args()

    try:
        args.func(args)
    except Exception, e:
        print e.message + "\n"


def restart_apache(args):
    _restart_apache(args.domain)


def _restart_apache(domain):
    print "\nRestarting your apache server"

    distro_name = _determine_platform()
    command = APACHE_COMMANDS.get(distro_name)
    print subprocess.call(command, shell=True)

    if domain:
        print 'waiting for apache process...'
        time.sleep(4)

        apache_process_result = _check_for_apache_process(distro_name)
        site_result = _check_for_site_availability(domain)
        ssl_result = _check_for_site_openssl(domain)

        site_result = False
        ssl_result = False
        apache_process_result = _check_for_apache_process(distro_name)
        if apache_process_result:
            site_result = _check_for_site_availability(domain)
            if site_result:
                ssl_result = _check_for_site_openssl(domain)

        if not apache_process_result or not site_result or not ssl_result:
            print "An error occurred starting apache.  Please restore your previous configuration file"


def parse_apache(args):
    print "my job is to parse the apache configuration file and store a backup and update the ssl config"
    _parse_apache(args.domain, args.cert, args.key, args.chain, args.apache_config)


def _parse_apache(host, cert, key, chain, apache_config=None):
    if host and cert and key and chain:
        try:
            apache_parser = BaseParser(host, cert, key, chain)
            apache_parser.load_apache_configs(apache_config)
            virtual_host = apache_parser.get_vhost_path_by_domain()
            apache_parser.set_certificate_directives(virtual_host)
        except Exception as e:
            print e.message


def _get_temp_api_key():
    # prompt for username and password,
    print "You will need your Digicert account credentials to continue: "

    username = raw_input("DigiCert Username: ")
    password = getpass.getpass("DigiCert Password: ")

    result = Request(action=LoginCommand(username, password), host=HOST).send()
    if result['http_status'] >= 300:
        raise Exception('Download failed:  %d - %s' % (result['http_status'], result['http_reason']))

    try:
        api_key = result['api_key']
        return api_key
    except KeyError:
        api_key = None
    return


def download_cert(args):
    global API_KEY
    API_KEY = args.api_key

    order_id = args.order_id
    domain = args.domain

    if not order_id and not domain:
        order = _select_from_orders()
        order_id = order['id']
        domain = order['certificate']['common_name']

    if not order_id and domain:
        order_id = _get_order_by_domain(domain)

    _download_cert(order_id, args.file_path, domain)


def _download_cert(order_id, file_path=None, domain=None):
    print "\nDownloading certificate files from digicert.com with order_id %s" % order_id
    global API_KEY

    if not API_KEY:
        API_KEY = _get_temp_api_key()

    if API_KEY:
        # if account_id:
        #     orderclient = CertificateOrder(HOST, API_KEY, customer_name=account_id)
        # else:
        #     orderclient = CertificateOrder(HOST, API_KEY)
        orderclient = CertificateOrder(HOST, API_KEY)
        certificates = orderclient.download(digicert_order_id=order_id)

        if '-----' not in certificates: # then we know this is a zip file containing all certs
            zip_file = ZipFile(StringIO(certificates))
            zip_file.extractall(file_path)
            return

        certificates = certificates.get('certificates')
        if not certificates:
            raise Exception("Failed to get certificates from order ".format(order_id))

        cert_file_path = os.path.join(file_path, 'cert.crt')

        if domain:
            cert_file_path = os.path.join(file_path, '{0}.crt'.format(domain.replace(".", "_")))

        chain_file_path = os.path.join(file_path, 'chain.pem')
        if domain:
            chain_file_path = os.path.join(file_path, '{0}.pem'.format(domain.replace(".", "_")))

        try:
            # create the download directory if it does not exist
            if file_path and not os.path.exists(file_path):
                os.mkdir(file_path)

            # download the certificate
            cert = certificates.get('certificate')
            cert_file = open(cert_file_path, 'w')
            cert_file.write(cert)
            cert_file.close()

            # download the intermediate certificate
            chain = certificates.get('intermediate')
            chain_file = open(chain_file_path, 'w')
            chain_file.write(chain)
            chain_file.close()
        except IOError as ioe:
            raise Exception("Download failed: {0}".format(ioe))

        return {'cert': cert_file_path, 'chain': chain_file_path}
    else:
        raise Exception('Username or API Key required to download certificate.')


# FIXME not currently used in any use case, we need to add this where it belongs
def create_csr_from_order(args):
    global API_KEY
    API_KEY = args.api_key
    order_id = args.order_id

    order_info = _get_order_info(API_KEY, order_id)
    if order_info['status'] and order_info['status'] == 'issued':
        certificate = order_info['certificate']
        if certificate:
            server_name = certificate['common_name']
            org_info = order_info['organization']

            if org_info:
                _create_csr(server_name, org_info['name'], org_info['city'], org_info['state'], org_info['country'])
            else:
                raise Exception("ERROR: We could not find your organization's information "
                                "for order #{0}".format(order_id))
        else:
            raise Exception("ERROR: We could not find a certificate for order #{0}".format(order_id))
    else:
        raise Exception("ERROR: Order #{0} has not been issued.".format(order_id))


def _get_order_info(order_id):
    global API_KEY
    print "my job is to get the order info for the certificate from digicert.com using the digicert_client module " \
          "with order_id %s" % order_id

    if not API_KEY:
        API_KEY = _get_temp_api_key()

    if API_KEY:
        # call the V2 view order API
        orderclient = CertificateOrder(HOST, API_KEY)
        order_info = orderclient.view(digicert_order_id=order_id)
        if order_info:
            return order_info
        else:
            raise Exception("ERROR: We could not find any information regarding order #{0}.".format(order_id))


def _get_valid_orders():
    global API_KEY

    if not API_KEY:
        API_KEY = _get_temp_api_key()

    if API_KEY:
        # call the V2 view orders API
        orders = list()
        orderclient = CertificateOrder(HOST, API_KEY)
        all_orders = orderclient.view_all()
        if all_orders:
            orders = list()
            for order in all_orders['orders']:
                if order['status'] == 'issued':
                    cert = order['certificate']
                    if cert:
                        orders.append(order)
            return orders
        else:
            raise Exception("ERROR: We could not find any orders for your account.")
        return


def _get_order_by_domain(domain):
    orders = _get_valid_orders()
    for order in orders:
        cert = order['certificate']

        # match the domain name to the common name on the order
        common_name = cert['common_name']
        if common_name == domain:
            return order['id']

        # if not a direct match, look for a wildcard match
        if "*." in common_name and common_name.replace("*.", "").strip() in domain:
            return order['id']


def _select_from_orders():
    orders = _get_valid_orders()
    i = 1
    for order in orders:
        print "{0}.\t{1}".format(i, order['certificate']['common_name'])
        i += 1
    resp = None
    while not resp or resp == "" or resp.isalpha():
        resp = raw_input("\nPlease select the domain you wish to secure from the list above: ")
    selection = int(resp) - 1

    print "You selected: {0}\n".format(orders[selection]['certificate']['common_name'])
    return orders[selection]



def _create_csr(server_name, org, city, state, country, key_size=2048):
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
    _copy_cert(args.cert_path, args.apache_path)


def _copy_cert(cert_path, apache_path):
    shutil.copyfile(cert_path, apache_path)


def do_everything(args):
    global API_KEY
    API_KEY = args.api_key
    order_id = args.order_id
    domain = args.domain
    key = args.key

    if not order_id and not domain:
        order = _select_from_orders()
        order_id = order['id']
        domain = order['certificate']['common_name']

    if not order_id and domain:
        order_id = _get_order_by_domain(domain)

    if order_id:
        # FIXME this will probably need to change once we've got creating the CSR worked out..
        if not key:
            key = raw_input("Please enter the absolute path to you the key file you created with"
                            " your CSR (ie: /etc/digicert/domain_name.key): ")

        # get the order info if the domain was not passed in the args
        if not domain:
            order_info = _get_order_info(order_id)
            certificate = order_info['certificate']
            if certificate:
                domain = certificate['common_name']

        certs = _download_cert(order_id, args.file_path, domain)
        chain = certs['chain']
        cert = certs['cert']

        # make the changes to apache
        _parse_apache(domain, cert, key, chain)

        # FIXME do we need to copy the cert in this scenario?
        # _copy_cert(cert_path, apache_path)
        print "\nEnabling SSL for your apache server"
        if _determine_platform() != 'CentOS' and not _is_ssl_mod_enabled('/usr/sbin/apachectl'):
            _enable_ssl_mod()
            _restart_apache(domain)
    else:
        print "ERROR: You must specify a valid domain or order id"


def _enable_ssl_mod():
    try:
        subprocess.check_call(["sudo", '/usr/sbin/a2enmod', 'ssl'], stdout=open("/dev/null", 'w'), stderr=open("/dev/null", 'w'))
        # TODO: add method to restart apache here
    except (OSError, subprocess.CalledProcessError) as err:
        raise Exception("There was a problem enabling mod_ssl.  Run 'sudo a2enmod ssl' to enable it or check the apache log for more information")


def _is_ssl_mod_enabled(apache_ctl):
    try:
        proc = subprocess.Popen([apache_ctl, '-M'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = proc.communicate()
    except:
        raise Exception("There was a problem acessing 'apachectl'")

    if 'ssl' in stdout:
        return True
    return False


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
    print "verifying {0} is available over HTTPS".format(domain)
    conn = HTTPSConnection(domain)
    conn.request('GET', '/')
    response = conn.getresponse()
    site_status = False
    if response.status == 200:
        print "{0} is reachable over HTTPS".format(domain)
        site_status = True

    return site_status


def _check_for_site_openssl(domain):
    # openssl s_client -connect domain.com:443
    print "validating the SSL configuration for {0}".format(domain)
    process = os.popen("openssl s_client -connect %s:443" % domain).read().splitlines()
    site_status = False
    if 'CONNECTED' in process:
        print "SSL configuration for {0} is valid".format(domain)
        site_status = True
    return site_status


def check_for_deps(args):
    distro = platform.linux_distribution()
    if distro == 'CentOS':
        check_for_deps_centos()
    else:
        check_for_deps_debian()


def check_for_deps_debian():
    # check to see which of the deps are installed
    try:
        a = apt.cache.Cache(memonly=True)

        for d in DEB_DEPS_64:
            if a[d].is_installed:
                continue
            else:
                answer = raw_input('Install: %s (y/n) ' % a[d].name)
                if answer.lower() == 'y':
                    a[d].mark_install()
                else:
                    print "Please install %s package yourself: " % a[d].name
                    raw_input("Press enter to continue: ")
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
                        print "Please install %s package yourself: " % package_name
                        raw_input("Press enter to continue: ")
    except ImportError:
        pass


if __name__ == '__main__':
    run()
