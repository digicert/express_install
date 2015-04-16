#!/usr/bin/env python

import os
import argparse
import subprocess
import platform
import shutil
import getpass
from httplib import HTTPSConnection
from httplib import HTTPException
import tempfile
from datetime import datetime
from zipfile import ZipFile
from StringIO import StringIO

from parsers.base import BaseParser
from loggers.express_install_logger import ExpressInstallLogger
from cqrs import LoginCommand
from digicert_client import CertificateOrder, Request

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

DEB_DEPS_64 = ['augeas-lenses', 'augeas-tools', 'libaugeas0', 'openssl', 'python-pip']
DEB_DEPS_32 = ['augeas-lenses', 'augeas-tools:i386', 'libaugeas0:i386', 'openssl', 'python-pip']

RH_DEPS = ['openssl', 'augeas-libs', 'augeas', 'python-pip', 'mod_ssl']

HOST = 'localhost.digicert.com'

API_KEY = None

CFG_PATH = '/etc/digicert'
LOGFILE = 'digicert_express.log'
LOGGER = ExpressInstallLogger(file_name=LOGFILE).get_logger()


def run():

    if os.geteuid() != 0:
        print 'DigiCert Express Install must be run as root.'
        exit()

    parser = argparse.ArgumentParser(description='Express Install. Let DigiCert manage your certificates for you!  '
                                                 'Run the following commands in the order shown below, or choose "all" to do everything in one step.')
    parser.add_argument('--version', action='version', version='Express Install 1.0.0b7')
    subparsers = parser.add_subparsers(help='Choose from the command options below:')

    dependency_check_parser = subparsers.add_parser('dep_check', help="Check for and install any needed dependencies")
    dependency_check_parser.add_argument("--verbose", action="store_true", help="Display verbose output")
    dependency_check_parser.set_defaults(func=check_for_deps)


    download_cert_parser = subparsers.add_parser('download_cert', help='Download certificate files from DigiCert')
    download_cert_parser.add_argument("--order_id", action="store", help="DigiCert order ID for certificate")
    download_cert_parser.add_argument("--domain", action="store", help="Domain name for the certificate")
    download_cert_parser.add_argument("--api_key", action="store", nargs="?", help="Skip authentication step with a DigiCert API key")
    download_cert_parser.set_defaults(func=download_cert)


    configure_apache_parser = subparsers.add_parser("configure_apache", help="Update Apache configuration with SSL settings")
    configure_apache_parser.add_argument("--domain", action="store", help="Domain name to secure")
    configure_apache_parser.add_argument("--cert", action="store", help="Absolute path to certificate file")
    configure_apache_parser.add_argument("--key", action="store", help="Absolute path to private key file")
    configure_apache_parser.add_argument("--chain", action="store", help="Absolute path to the certificate chain (intermediate)")
    configure_apache_parser.add_argument("--apache_config", action="store", default=None,
                          help="If you know the path your Virtual Host file or main Apache configuration file please "
                               "include it here, if not we will try to find it for you")
    configure_apache_parser.add_argument("--dry_run", action="store_true", help="Display what changes will be made without making any changes")
    configure_apache_parser.set_defaults(func=configure_apache)

    restart_apache_parser = subparsers.add_parser('restart_apache', help='Restart Apache and verify SSL configuration')
    restart_apache_parser.add_argument("--domain", action="store", nargs="?", help="Domain to verify after the restart")
    restart_apache_parser.add_argument("--verbose", action="store_true", help="Display verbose output")
    restart_apache_parser.set_defaults(func=restart_apache)

    all_parser = subparsers.add_parser("all", help='Download your certificate and secure your domain in one step')
    all_parser.add_argument("--domain", action="store", help="Domain name to secure")
    all_parser.add_argument("--key", action="store", help="Path to private key file used to order certificate")
    all_parser.add_argument("--api_key", action="store", help="Skip authentication step with a DigiCert API key")
    all_parser.add_argument("--order_id", action="store", help="DigiCert order ID for certificate")
    all_parser.add_argument("--create_csr", action="store_true", help="Create and upload the csr, this will also create the private key file")
    all_parser.add_argument("--dry_run", action="store_true", help="Display what changes will be made without making any changes")
    all_parser.add_argument("--restart_apache", action="store_true", help="Restart Apache server without prompting")
    all_parser.add_argument("--verbose", action="store_true", help="Display verbose output")
    all_parser.set_defaults(func=do_everything)

    args = parser.parse_args()

    try:
        print ''
        LOGGER.info('DigiCert Express Install')
        print ''
        args.func(args)
    except Exception, e:
        LOGGER.error(e.message)
        print ''


def restart_apache(args):
    _restart_apache(args.domain, args.verbose)


def _restart_apache(domain='', verbose=False):
    LOGGER.info("Restarting your apache server")

    distro_name = _determine_platform()
    command = APACHE_COMMANDS.get(distro_name)
    if not verbose:
        command += " 2>/dev/null"
    subprocess.call(command, shell=True)

    have_error = False
    apache_process_result = _check_for_apache_process(distro_name)

    if not apache_process_result:
        LOGGER.error("ERROR: Apache did not restart successfully.")
        have_error = True

    if domain and apache_process_result:
        site_result = _check_for_site_availability(domain)
        ssl_result = False
        if site_result:
            ssl_result = _check_for_site_openssl(domain)

        if not site_result:
            LOGGER.error("ERROR: Could not connect to the domain %s via HTTPS." % domain)
            have_error = True

        if not ssl_result:
            LOGGER.error("ERROR: Could not connect")
            have_error = True

    if not have_error:
        LOGGER.info('Apache restarted successfully.')
        print ''


def configure_apache(args):
    domain = args.domain
    cert = args.cert
    chain = args.chain
    key = args.key

    if not domain:
        order = _select_from_orders()
        if order:
            domain = order['certificate']['common_name']
            common_name = domain
    else:
        order = _get_order_by_domain(domain)
        if order:
            common_name = order['certificate']['common_name']

    LOGGER.info("Updating the Apache configuration with SSL settings.")

    if not cert:
        cert = _locate_cfg_file('%s.crt' % common_name.replace('.', '_'), 'Certificate')
        if not cert:
            LOGGER.error('No valid certificate file located; aborting.')
            return

    if not chain:
        chain = _locate_cfg_file(['%s.pem' % common_name.replace('.', '_'), 'DigiCertCA.crt'], 'Certificate chain')
        if not chain:
            LOGGER.error('No valid certificate chain file located; aborting.')
            return

    if not key:
        key = _locate_cfg_file('%s.key' % common_name.replace('.', '_'), 'Private key', validate_key=True, cert=cert)
        if not key:
            LOGGER.error('No valid private key file located; aborting.')
            return

    _configure_apache(domain, cert, key, chain, args.apache_config, args.dry_run)

    if not args.dry_run:
        LOGGER.info('Please restart Apache for your changes to take effect.')


def _locate_cfg_file(cfg_file_names, file_type, prompt=True, validate_key=False, cert=None):
    LOGGER.info("Looking for {0}...".format(file_type))
    if isinstance(cfg_file_names, basestring):
        names = [cfg_file_names]
    else:
        names = cfg_file_names
    for cfg_file_name in names:
        file_path = os.path.join(CFG_PATH, cfg_file_name)
        if os.path.exists(file_path):
            return_file = True
            if validate_key:
                if not cert or not _validate_key(file_path, cert):
                    return_file = False
            if return_file:
                return file_path

    # Search the filesystem
    for cfg_file_name in names:
        command = "find / -type f -name {0}".format(cfg_file_name)
        files = os.popen(command).read().splitlines()
        if len(files) > 0:
            matching_files = list()
            for file in files:
                if validate_key:
                    if cert and _validate_key(file, cert):
                        matching_files.append(file)
                else:
                    matching_files.append(file)

            if len(matching_files) == 1:
                return matching_files[0]
            else:
                resp = None
                while not resp:
                    for i in range(0, len(matching_files)):
                        print "{0}.\t{1}".format(i + 1, matching_files[i])

                    resp = raw_input("\nPlease select the {0} you wish to secure "
                                     "from the list above (q to quit): ".format(file_type))

                    if resp != 'q':
                        # validate the input, catch any exceptions from casting to an int and validate the
                        # int value makes sense
                        try:
                            if int(resp) > len(matching_files) or int(resp) < 0:
                                raise Exception
                        except Exception as e:
                            resp = None
                            print ""
                            print "ERROR: Invalid number, please try again."
                            print ""
                    else:
                        continue
                if resp and resp != 'q':
                    selection = int(resp) - 1
                    return matching_files[selection]

    if prompt:
        # At this point we haven't found any matching files so we need to prompt for one
        file_path = None
        try:
            while not file_path:
                try:
                    file_path = raw_input('%s file could not be found.  Please provide a path to the file: ' % file_type)
                    if os.path.exists(file_path):
                        if validate_key and cert:
                            if not _validate_key(file_path, cert):
                                raise Exception("This key ({0}) does not match your certificate ({1}), please try again.".format(file_path, cert))
                            else:
                                break
                        else:
                            break
                    if len(file_path):
                        raise Exception('No such file or directory: "%s"' % file_path)
                    file_path = None
                except Exception, e:
                    file_path = None
                    print e.message
                    print ''
        except KeyboardInterrupt:
            print ''
            LOGGER.error('No valid file selected.')
            print ''
        return file_path


def _validate_key(key, cert):
    key_command = "openssl rsa -noout -modulus -in \"{0}\" | openssl md5".format(key)
    crt_command = "openssl x509 -noout -modulus -in \"{0}\" | openssl md5".format(cert)

    key_modulus = os.popen(key_command).read()
    crt_modulus = os.popen(crt_command).read()

    return key_modulus == crt_modulus


def _configure_apache(host, cert, key, chain, apache_config=None, dry_run=False):
    LOGGER.info('Parsing Apache configuration...')
    apache_parser = BaseParser(host, cert, key, chain, CFG_PATH, logger=LOGGER, dry_run=dry_run)
    apache_parser.load_apache_configs(apache_config)
    virtual_host = apache_parser.get_vhost_path_by_domain()

    LOGGER.info('Updating Apache configuration...')
    apache_parser.set_certificate_directives(virtual_host)

    _enable_ssl_mod()

    if not dry_run:
        LOGGER.info('Apache configuration updated successfully.')
        print ''


def _get_temp_api_key():
    # prompt for username and password,
    LOGGER.info("You will need your Digicert account credentials to continue: ")

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

    if not order_id and domain:
        order = _get_order_by_domain(domain)

    if order:
        order_id = order['id']
        domain = order['certificate']['common_name']

    _download_cert(order_id, CFG_PATH, domain)


def _download_cert(order_id, file_path=None, domain=None):
    msg_downloading = 'Downloading certificate files for'
    msg_from_dc = 'from digicert.com'
    if domain:
        LOGGER.info('%s domain "%s" %s (Order ID: %s)...' % (msg_downloading, domain, msg_from_dc, order_id))
    else:
        LOGGER.info('%s order ID "%s" %s...' % (msg_downloading, order_id, msg_from_dc))
    print ''

    global API_KEY

    if not API_KEY:
        API_KEY = _get_temp_api_key()

    if API_KEY:
        orderclient = CertificateOrder(HOST, API_KEY)
        certificates = orderclient.download(digicert_order_id=order_id)

        cert_file_path = os.path.join(file_path, 'cert.crt')
        chain_file_path = os.path.join(file_path, 'chain.pem')

        try:
            # create the download directory if it does not exist
            if file_path and not os.path.exists(file_path):
                os.mkdir(file_path)
                LOGGER.info('Created %s directory...' % file_path)

            if isinstance(certificates, str):
                # then we know this is a zip file containing all certs
                zip_file = ZipFile(StringIO(certificates))
                tmp_dir = tempfile.gettempdir()
                zip_file.extractall(tmp_dir)

                # get the files that were extracted
                cert_dir = os.path.join(tmp_dir, "certs")
                src_cert_file_path = os.path.join(cert_dir, '{0}.crt'.format(domain.replace(".", "_")))
                src_chain_file_path = os.path.join(cert_dir, 'DigiCertCA.crt')
                cert_file_path = os.path.join(file_path, os.path.basename(src_cert_file_path))
                chain_file_path = os.path.join(file_path, os.path.basename(src_chain_file_path))
                _copy_cert(src_cert_file_path, cert_file_path)
                _copy_cert(src_chain_file_path, chain_file_path)
            else:
                certificates = certificates.get('certificates')
                if not certificates:
                    raise Exception("Failed to get certificates from order ".format(order_id))

                if domain:
                    cert_file_path = os.path.join(file_path, '{0}.crt'.format(domain.replace(".", "_")))
                    chain_file_path = os.path.join(file_path, '{0}.pem'.format(domain.replace(".", "_")))

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

        LOGGER.info('Created certificate file at path %s...' % cert_file_path)
        LOGGER.info('Created certificate chain file at path %s...' % chain_file_path)
        print ''
        LOGGER.info('Certificate files downloaded successfully.')
        print ''

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


def _upload_csr(order_id, csr_file):
    LOGGER.info("Uploading CSR file for order# {0}...".format(order_id))
    global API_KEY

    if not API_KEY:
        API_KEY = _get_temp_api_key()

    if API_KEY:
        # call the V2 view orders API
        csr_text = None
        with open(csr_file, "r") as f:
            csr_text = f.read()

        orderclient = CertificateOrder(HOST, API_KEY)
        resp = orderclient.upload_csr(order_id, csr_text)
        if resp and resp['http_status']:
            # accept any 2xx status code
            import math
            result = int(math.floor(int(resp['http_status']) / 100)) * 100
            if result == 200:
                LOGGER.info("CSR uploaded successfully")
                print ""
                return True
        return False


def _get_order_by_domain(domain):
    orders = _get_valid_orders()
    for order in orders:
        cert = order['certificate']

        # match the domain name to the common name on the order
        common_name = cert['common_name']
        if common_name == domain:
            return order

        if domain.startswith('www.'):
            if common_name == domain.split('.', 1)[1]:
                return order
        else:
            if common_name == 'www.%s' % domain:
                return order

        # if not a direct match, look for a wildcard match
        if "*." in common_name and common_name.replace("*.", "").strip() in domain:
            return order


def _select_from_orders():
    orders = _get_valid_orders()
    resp = None
    if len(orders) > 1:
        while not resp or resp == "" or resp.isalpha():
            i = 1
            for order in orders:
                print "{0}.\t{1}".format(i, order['certificate']['common_name'])
                i += 1

            resp = raw_input("\nPlease select the domain you wish to secure from the list above (q to quit): ")

            if resp != 'q':
                # validate the input, catch any exceptions from casting to an int and validate the int value makes sense
                try:
                    if int(resp) > len(orders) or int(resp) < 0:
                        raise Exception
                except Exception as e:
                    resp = None
                    print ""
                    print "ERROR: Invalid number, please try again."
                    print ""
            else:
                raise Exception("No domain selected; aborting.")

    else:
        # there is only one order, choose it
        order_id = orders[0]['id']
        domain = orders[0]['certificate']['common_name']
        if raw_input("Continue with certificate {0} (Order ID: {1})? (Y/n)".format(domain, order_id)) != 'n':
            resp = 1
        else:
            raise Exception("No certificate selected; aborting.")

    selection = int(resp) - 1
    return orders[selection]


def _create_csr(server_name, org="", city="", state="", country="", key_size=2048):
    LOGGER.info("Creating CSR file for {0}...".format(server_name))
    # remove http:// and https:// from server_name
    server_name = server_name.lstrip("http://")
    server_name = server_name.lstrip("https://")

    key_file_name = "{0}.key".format(server_name.replace('.', '_'))
    csr_file_name = "{0}.csr".format(server_name.replace('.', '_'))

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
    return {"key": key_file_name, "csr": csr_file_name}


def _copy_cert(cert_path, apache_path):
    shutil.copyfile(cert_path, apache_path)


def do_everything(args):
    global API_KEY
    API_KEY = args.api_key

    # check the dependencies
    check_for_deps(args)

    order_id = args.order_id
    domain = args.domain
    key = args.key

    # in some cases (*.domain.com, www.domain.com) the entered domain name could be slightly different
    # than the common name on the certificate, this really only matters when downloading the cert
    common_name = domain

    if not order_id and not domain:
        order = _select_from_orders()
        order_id = order['id']
        domain = order['certificate']['common_name']
        common_name = domain

    if not order_id and domain:
        order = _get_order_by_domain(domain)
        order_id = order['id']
        common_name = order['certificate']['common_name']

    if order_id:
        # get the order info if the domain was not passed in the args
        if not domain:
            order_info = _get_order_info(order_id)
            certificate = order_info['certificate']
            if certificate:
                domain = certificate['common_name']
                common_name = domain

        create_csr = args.create_csr
        if create_csr:
            # if the user specified a key or one was found then the csr may have already been generated, if another
            # is submitted and a new key is generated apache2 may not restart due to a key mismatch
            # FIXME we need to work out a 're-issue' scenario at some point
            if not key:
                key = _locate_cfg_file('%s.key' % common_name.replace('.', '_'), 'Private key')

            csr = None
            if key:
                # check the order status, if the status is needs_csr check for the csr file and upload it
                order_info = _get_order_info(order_id)
                if order_info['status'] == "needs_csr":
                    # if we found a key and the status is 'needs_csr' we expect to find the csr file as well
                    csr = _locate_cfg_file('%s.csr' % common_name.replace('.', '_'), 'CSR file', prompt=False)

                    if not csr:
                        # back up the existing key
                        timestamp = datetime.fromtimestamp(int(os.path.getctime(key))).strftime('%Y-%m-%d_%H:%M:%S')
                        shutil.copy(key, "{0}.{1}.bak".format(key, timestamp))
                        create_csr = True

                elif order_info['status'] == "issued":
                    LOGGER.info("It looks like you've already submitted your csr, we'll download and configure your certificates for you")
                    create_csr = False

            if create_csr:
                if not csr:
                    # create the csr and private key
                    csr_response = _create_csr(common_name)
                    key = csr_response['key']
                    csr = csr_response['csr']

                # upload the csr
                if not _upload_csr(order_id, csr):
                    LOGGER.error("We could not upload your csr file, please try again or contact DigiCert support.")
                    return

        cert = None
        chain = None
        if not create_csr:
            # if we didn't create the csr for them previously, their chain and cert could be on the filesystem
            # attempt to locate the cert and chain files
            # FIXME should we prompt the user to input the path to their files at this point?
            cert = _locate_cfg_file('%s.crt' % common_name.replace('.', '_'), 'Certificate', prompt=False)
            chain = _locate_cfg_file(['%s.pem' % common_name.replace('.', '_'), 'DigiCertCA.crt'], 'Certificate chain', prompt=False)

        # if we still don't have the cert and chain files, download them
        if not cert or not chain:
            certs = _download_cert(order_id, CFG_PATH, common_name)
            chain = certs['chain']
            cert = certs['cert']

        if not key:
            key = _locate_cfg_file('%s.key' % common_name.replace('.', '_'), 'Private key', validate_key=True, cert=cert)

        if not key:
            LOGGER.error('No valid private key file located; aborting.')
            return

        # make the changes to apache
        _configure_apache(domain, cert, key, chain, dry_run=args.dry_run)

        if not args.dry_run:
            if args.restart_apache or raw_input('Would you like to restart Apache now? (Y/n) ') != 'n':
                _restart_apache(domain, args.verbose)
                LOGGER.info("Congratulations, you've successfully installed your certificate to (%s)." % domain)
            else:
                LOGGER.info('Restart your Apache server for your changes to take effect.')
                LOGGER.info('Use the following command to restart your Apache server and verify your SSL settings:')
                LOGGER.info('sudo express_install restart_apache --domain "{0}"'.format(domain))
    else:
        LOGGER.error("ERROR: You must specify a valid domain or order id")


def _enable_ssl_mod():
    LOGGER.info('Enabling Apache SSL module...')
    if _determine_platform() != 'CentOS' and not _is_ssl_mod_enabled('/usr/sbin/apachectl'):
        try:
            subprocess.check_call(["sudo", '/usr/sbin/a2enmod', 'ssl'], stdout=open("/dev/null", 'w'), stderr=open("/dev/null", 'w'))
        except (OSError, subprocess.CalledProcessError) as err:
            raise Exception("There was a problem enabling mod_ssl.  Run 'sudo a2enmod ssl' to enable it or check the apache log for more information")


def _is_ssl_mod_enabled(apache_ctl):
    try:
        proc = subprocess.Popen([apache_ctl, '-M'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = proc.communicate()
    except:
        raise Exception("There was a problem accessing 'apachectl'")

    if 'ssl' in stdout:
        return True
    return False


def _determine_platform():
    distro_name = platform.linux_distribution()  # returns a tuple ('', '', '') (distroName, version, code name)
    return distro_name[0]


def _check_for_apache_process(platform_name):
    try:
        process_name = APACHE_PROCESS_NAMES.get(platform_name)
        process = os.popen("ps aux | grep %s" % process_name).read().splitlines()
        if len(process) > 2:
            return True
    except Exception, e:
        LOGGER.error("ERROR: %s" % e.message)
    return False


def _check_for_site_availability(domain):
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


def _check_for_site_openssl(domain):
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


def check_for_deps(args):
    distro = platform.linux_distribution()
    if distro == 'CentOS':
        check_for_deps_centos(args.verbose)
    else:
        check_for_deps_debian(args.verbose)


def check_for_deps_debian(verbose=False):
    # check to see which of the deps are installed
    try:
        import apt
        a = apt.cache.Cache(memonly=True)

        for d in DEB_DEPS_64:
            if a[d].is_installed:
                continue
            else:
                if raw_input('Install: %s (Y/n) ' % a[d].name).lower().strip() == 'n':
                    LOGGER.info("Please install %s package yourself: " % a[d].name)
                    raw_input("Press enter to continue: ")
                else:
                    LOGGER.info("Installing %s..." % a[d].name)
                    if verbose:
                        a[d].mark_install()
                    else:
                        os.system('apt-get -y install %s &>> %s' % (a[d].name, LOGFILE))
        if verbose:
            a.commit()
    except ImportError:
        pass


def check_for_deps_centos(verbose=False):
    try:
        import yum
        yb = yum.YumBase()
        packages = yb.rpmdb.returnPackages()
        for p in packages:
            for package_name in RH_DEPS:
                if package_name in [x.name for x in packages]:
                    continue
                else:
                    if raw_input('Install: %s (Y/n) ' % p.name).lower().strip() == 'n':
                        LOGGER.info("Please install %s package yourself: " % package_name)
                        raw_input("Press enter to continue: ")
                    else:
                        LOGGER.info("Installing %s..." % p.name)
                        if verbose:
                            yb.install(name=p.name)
                        else:
                            os.system('yum -y install %s &>> %s' % (p.name, LOGFILE))
    except ImportError:
        pass


if __name__ == '__main__':
    try:
        run()
    except KeyboardInterrupt:
        print
