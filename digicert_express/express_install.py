#!/usr/bin/env python

from distutils.version import StrictVersion
import argparse
import os
import shutil
import pkg_resources

import parsers
import express_utils
import express_client

from express_utils import LOGGER
from express_utils import CFG_PATH

"""
Module is the CLI interface the user interacts with.
Only contains the interface called directly from
the CLI and delegates off for core functionality.
"""


def run():
    if os.geteuid() != 0:
        print 'DigiCert Express Install must be run as root.'
        exit()

    parser = argparse.ArgumentParser(description='Express Install. Let DigiCert manage your certificates for you!  '
                                                 'Run the following commands in the order shown below, or choose "all" to do everything in one step.')
    parser.add_argument('--version', action='version', version='Express Install %s' % pkg_resources.require('digicert_express')[0].version)
    subparsers = parser.add_subparsers(help='Choose from the command options below:')

    dependency_check_parser = subparsers.add_parser('dep_check', help="Check for and install any needed dependencies")
    dependency_check_parser.set_defaults(func=check_for_deps)

    restart_apache_parser = subparsers.add_parser('restart_apache', help='Restart Apache and verify SSL configuration')
    restart_apache_parser.add_argument("--domain", action="store", nargs="?", help="Domain to verify after the restart")
    restart_apache_parser.set_defaults(func=restart_apache)

    all_parser = subparsers.add_parser("all", help='Download your certificate and secure your domain in one step')
    all_parser.add_argument("--domain", action="store", help="Domain name to secure")
    all_parser.add_argument("--key", action="store", help="Path to private key file used to order certificate")
    all_parser.add_argument("--api_key", action="store", help="Skip authentication step with a DigiCert API key")
    all_parser.add_argument("--order_id", action="store", help="DigiCert order ID for certificate")
    all_parser.set_defaults(func=do_everything)

    args = parser.parse_args()

    try:
        print ''
        LOGGER.info('DigiCert Express Install Web Server Configuration Utility')
        print ''
        verify_requirements()
        args.func(args)
    except Exception, e:
        raise e
        LOGGER.error(e)
        print ''


def restart_apache(args):
    express_utils.restart_apache()


def do_everything(args):
    # check the dependencies
    check_for_deps(args)

    order_id = args.order_id
    domain = args.domain
    api_key = args.api_key
    key = args.key
    do_everything_with_args(order_id=order_id, domain=domain, api_key=api_key, key=key)


def finalize_and_restart(domain):
    if raw_input('Would you like to restart Apache now? (Y/n) ') != 'n':
        express_utils.restart_apache()
        LOGGER.info("Congratulations, you've successfully installed your certificate to (%s)." % domain)
    else:
        LOGGER.info('Restart your Apache server for your changes to take effect.')
        LOGGER.info('Use the following command to restart your Apache server and verify your SSL settings:')
        LOGGER.info('sudo express_install restart_apache')


def do_everything_with_args(order_id='', domain='', api_key='', key=''):
    raw_input("I'll attempt to secure virtual hosts configured on this web server with an SSL certificate.  Press ENTER to continue.")
    print ''
    LOGGER.info("Looking up order info")
    order_id, domain, common_name = express_client.get_order_and_domain_info(order_id, domain)

    if order_id:  #and not domain:
        # 1.  get the order info for order_id, domain and common_name
        LOGGER.info("Querying for issued certificates with order_id %s" % order_id)

        # 2.  look for key, chain and csr
        cert = parsers.locate_cfg_file('%s.crt' % express_utils.replace_chars(common_name), 'Certificate', prompt=False,
                                           default_search_path="{0}/{1}".format(CFG_PATH, express_utils.replace_chars(domain)))
        chain = parsers.locate_cfg_file(['DigiCertCA.crt'], 'Certificate chain', prompt=False,
                                           default_search_path="{0}/{1}".format(CFG_PATH, express_utils.replace_chars(domain)))
        key = parsers.locate_cfg_file('%s.key' % express_utils.replace_chars(common_name), 'Private key', validate_key=True,
                                          cert=cert,
                                          default_search_path="{0}/{1}".format(CFG_PATH, express_utils.replace_chars(domain)))

        if cert and chain and key:
            LOGGER.info("Found cert, chain and key")
            LOGGER.info("Installing cert for domain: %s" % domain)

            dns_names = express_utils.get_dns_names_from_openssl(cert)

            _install_multidomain_cert(order_id, domain, dns_names, cert, key=key, chain=chain)
            finalize_and_restart(domain)
            return

        if not cert and not chain and not key:
            LOGGER.info("Did not find cert, chain and key, proceeding...")
            _process(domain, order_id, failed_pk_check=False)
            finalize_and_restart(domain)
            return

        if cert and chain and not key:
            LOGGER.info("Found cert and chain but not key, proceeding...")
            _process(domain, order_id, failed_pk_check=True)
            finalize_and_restart(domain)
            return
    else:
        LOGGER.error("ERROR: You must specify a valid domain or order id")


def verify_requirements():
    LOGGER.info("Verifying minimum requirements are met. ")
    os_name, os_version, code_name = express_utils.determine_platform()
    python_version = express_utils.determine_python_version()
    apache_version = express_utils.determine_apache_version(os_name)

    errors = []
    if apache_version:
        if os_name == 'Ubuntu':
            if StrictVersion(os_version) < StrictVersion('14.04'):
                errors.append(
                    "Your version of Ubuntu (%s) is not supported.  Ubuntu version 14.04 or higher is required." % os_version)
            if StrictVersion(python_version) < StrictVersion('2.7'):
                errors.append(
                    "Your version of Python (%s) is not supported.  Python version 2.7 or higher is required." % python_version)
            if StrictVersion(apache_version) < StrictVersion('2.4'):
                errors.append(
                    "Your version of Apache (%s) is not supported.  Apache version 2.4 or higher is required." % apache_version)
        elif os_name == 'CentOS':
            if StrictVersion(os_version) < StrictVersion('6.5'):
                errors.append(
                    "Your version of CentOS (%s) is not supported.  CentOS version 6.5 or higher is required." % os_version)
            if StrictVersion(python_version) < StrictVersion('2.6'):
                errors.append(
                    "Your version of Python (%s) is not supported.  Python version 2.6 or higher is required." % python_version)
            if StrictVersion(apache_version) < StrictVersion('2.2'):
                errors.append(
                    "Your version of Apache (%s) is not supported.  Apache version 2.2 or higher is required." % apache_version)
        else:
            errors.append("%s %s is not a supported operating system.  Ubuntu 14.04 and CentOS 6.5 are supported." % (os_name, os_version))
    else:
        errors.append("No Apache version detected, please verify that Apache is installed and running")

    if len(errors) > 0:
        if 'localhost' not in express_utils.HOST:
            error_msg = "ERROR: Your system does not meet the minimum requirements to run this program:"
            LOGGER.info(error_msg)
            LOGGER.info("\n".join(errors))
            for error in errors:
                error_msg = "%s\n%s" % (error_msg, error)
            raise Exception(error_msg)
    else:
        LOGGER.info("Minimum requirements are met")


def check_for_deps(args):
    distro = express_utils.determine_platform()
    if distro[0] == 'CentOS':
        express_utils.check_for_deps_centos()
    else:
        express_utils.check_for_deps_ubuntu()


def _process(domain, order_id, failed_pk_check=False):
    order_info = express_client.get_order_info(order_id)
    api_key = order_info.get('api_key')
    if order_info.get('status') != 'issued':
        if order_info.get('status') == 'needs_csr':
            LOGGER.info("Order needs a CSR.")
            private_key_file, csr_file = express_utils.create_csr(domain)
            express_client.upload_csr(order_id, csr_file, api_key=api_key)
            order_info = express_client.get_order_info(order_id, api_key=api_key)
            if order_info.get('status') == 'issued':
                LOGGER.info("Order is issued")

                if order_info.get('allow_duplicates'):
                    cert, chain, key = _download_multidomain_cert(order_id, domain, domains=order_info.get('certificate').get('dns_names'), private_key=private_key_file, api_key=api_key, create_duplicate=False)
                    _install_multidomain_cert(order_id, domain, domains=order_info.get('certificate').get('dns_names'), cert=cert, key=private_key_file, chain=chain, api_key=api_key)
                else:
                    _download_and_install_cert(order_id, domain, private_key=private_key_file, api_key=api_key, create_csr=False)
                return
            # TODO: we may need to add better handling for csr if it exists
        raise Exception('This certificate cannot be installed at this time because something happened getting the status back from the site')
    else:
        if order_info.get('allow_duplicates'):
            response = raw_input("Do you want to create and install a duplicate for a certificate? \n Answering no will attempt to install the original certificate.  [y/n] ")
            LOGGER.info("Do you want to create and install a duplicate for a certificate? \n Answering no will attempt to install the original certificate.  [y/n] ")
            LOGGER.info("Duplicate Response: %s" % response)
            if response.lower().strip() == 'y': # TODO: make this more robust
                cert, chain, key = _download_multidomain_cert(order_id, domain, domains=order_info.get('certificate').get('dns_names'), api_key=api_key, create_duplicate=True)
                _install_multidomain_cert(order_id, domain, domains=order_info.get('certificate').get('dns_names'), cert=cert, key=key, chain=chain)
            else:
                if not failed_pk_check:
                    _download_and_install_cert(order_id, domain, api_key=api_key, create_csr=False)
                else:
                    raise Exception('This certificate cannot be installed at this time because it failed the pk check.')
        else:
            if not failed_pk_check:
                LOGGER.info("Order does not support duplicates")
                _download_and_install_cert(order_id, domain, api_key=api_key, create_csr=False)
            else:
                raise Exception('This certificate cannot be installed at this time')


def _download_and_install_cert(order_id, domain, private_key='', api_key='', create_csr=False):
    LOGGER.info("Attempting to download the cert")
    private_key_file = private_key
    if create_csr:
        private_key_file, csr_file = express_utils.create_csr(domain)
        express_client.upload_csr(order_id, csr_file, api_key) # TODO: maybe catch result to see if successful

    certs = express_client.download_cert(order_id, CFG_PATH, domain, api_key=api_key)
    chain = certs.get('chain', None)
    cert = certs.get('cert', None)
    key = private_key_file
    if not key:
        key = parsers.locate_cfg_file('%s.key' % domain.replace('.', '_'), 'Private key', validate_key=True,
                                          cert=cert,
                                          default_search_path="{0}/{1}".format(CFG_PATH, domain.replace('.', '_')))

    if not key:
        raise Exception('Could not find private key')

    LOGGER.info("Installing cert for domain: %s" % domain)
    parsers.configure_apache(domain, cert, key, chain)

    cleanup()

    return


def _download_multidomain_cert(order_id, common_name, domains, private_key='', api_key='', create_duplicate=False):
    LOGGER.info("Getting ready to download the certificate.")
    key = private_key
    if create_duplicate:
        LOGGER.info("Creating duplicate certificate")
        private_key_file, csr_file = express_utils.create_csr(common_name)

        csr = open(csr_file, 'r').read()
        duplicate_cert_data = {"certificate": {"common_name": common_name, "csr": csr, "signature_hash": "sha256", "server_platform": {"id": 2}, "dns_names": domains}}

        result = express_client.create_duplicate(order_id, duplicate_cert_data, api_key=api_key)
        LOGGER.info("Please wait a few seconds")
        import time
        time.sleep(12)
        if not result.get('sub_id'):
            raise Exception("Order: %s needs to have administrator approval to proceed.  Please contact your administrator or DigiCert Support for help. " % order_id)
        duplicate_cert = express_client.get_duplicate(order_id, result.get('sub_id'), CFG_PATH, common_name, api_key=api_key)
        cert = duplicate_cert.get("cert", None)
        chain = duplicate_cert.get("chain", None)
        key = private_key_file
    else:
        certs = express_client.download_cert(order_id, CFG_PATH, common_name, api_key=api_key)
        chain = certs.get('chain', None)
        cert = certs.get('cert', None)

    if not key:
        raise Exception('Could not find private key')

    return cert, chain, key


def _install_multidomain_cert(order_id, common_name, domains, cert, key, chain, api_key=''):
    # get all virtual hosts
    apache_parser = parsers.prepare_parser(common_name, cert, key, chain)
    LOGGER.info("Now, getting the vhosts that are on this server")
    virtual_hosts = apache_parser.get_vhosts_on_server()

    # find matches from virtuals hosts and domains
    matched_hosts = parsers.compare_match(virtual_hosts, domains)
    LOGGER.info("Found matching host: %s" % "\n".join(matched_hosts))

    if not matched_hosts:
        raise Exception("Didn't find any virtual hosts on this web server matching the domains for this certificate")

    # prepare menu selection for the user to choose which virtual hosts to configure
    choices = zip(range(1, len(matched_hosts)+1), matched_hosts)
    doc_hosts = list()
    for choice in choices:
        s = [str(a) for a in choice]
        doc_hosts.append(". ".join(s))
    prompt_hosts = "\n".join(doc_hosts)
    LOGGER.info("The following virtual hosts on this server match the certificate. ")
    LOGGER.info(prompt_hosts)
    selected = raw_input("Choose which hosts to configure:\nEnter comma separated numbers to select multiple hosts.  IE 1,2,3\n")

    # from user input, determine the domains chosen.
    selection = selected.split(',')
    selected_hosts = []
    for x in selection:
        for choice in choices:
            if int(x) == choice[0]:
                LOGGER.info("User selected host: %s" % choice[1])
                selected_hosts.append(choice[1])

    # finally, configure apache
    for host in selected_hosts:
        LOGGER.info("Installing cert for domain: %s" % host)
        apache_parser.common_name = host
        parsers.configure_apache(host, apache_parser.cert_path, apache_parser.key_path, apache_parser.chain_path, is_multidomain=True)

    cleanup()

    return


def cleanup():
    LOGGER.info("Cleaning up files")
    for path in os.listdir(CFG_PATH):
        if path.endswith('.crt'):
            os.remove(CFG_PATH + '/' + path)

    if os.path.exists('/tmp/certs'):
        shutil.rmtree('/tmp/certs')


if __name__ == '__main__':
    try:
        run()
        print 'Finished'
    except KeyboardInterrupt:
        print
