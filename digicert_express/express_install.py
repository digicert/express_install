#!/usr/bin/env python

from distutils.version import StrictVersion
import argparse

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
    # if os.geteuid() != 0:
    #     print 'DigiCert Express Install must be run as root.'
    #     exit()

    #TODO: review all options and parsers
    parser = argparse.ArgumentParser(description='Express Install. Let DigiCert manage your certificates for you!  '
                                                 'Run the following commands in the order shown below, or choose "all" to do everything in one step.')
    parser.add_argument('--version', action='version', version='Express Install 1.1.01')
    subparsers = parser.add_subparsers(help='Choose from the command options below:')

    dependency_check_parser = subparsers.add_parser('dep_check', help="Check for and install any needed dependencies")
    dependency_check_parser.add_argument("--verbose", action="store_true", help="Display verbose output")
    dependency_check_parser.set_defaults(func=check_for_deps)

    download_cert_parser = subparsers.add_parser('download_cert', help='Download certificate files from DigiCert')
    download_cert_parser.add_argument("--order_id", action="store", help="DigiCert order ID for certificate")
    download_cert_parser.add_argument("--domain", action="store", help="Domain name for the certificate")
    download_cert_parser.add_argument("--api_key", action="store", nargs="?",
                                      help="Skip authentication step with a DigiCert API key")
    download_cert_parser.set_defaults(func=download_cert)

    configure_apache_parser = subparsers.add_parser("configure_apache", help="Update Apache configuration with SSL settings")
    configure_apache_parser.add_argument("--domain", action="store", help="Domain name to secure")
    configure_apache_parser.add_argument("--cert", action="store", help="Absolute path to certificate file")
    configure_apache_parser.add_argument("--key", action="store", help="Absolute path to private key file")
    configure_apache_parser.add_argument("--chain", action="store",
                                         help="Absolute path to the certificate chain (intermediate)")
    configure_apache_parser.add_argument("--apache_config", action="store", default=None,
                                         help="If you know the path your Virtual Host file or main Apache configuration file please "
                                              "include it here, if not we will try to find it for you")
    configure_apache_parser.add_argument("--dry_run", action="store_true",
                                         help="Display what changes will be made without making any changes")
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
    all_parser.add_argument("--create_csr", action="store_true",
                            help="Create and upload the csr, this will also create the private key file")
    all_parser.add_argument("--dry_run", action="store_true",
                            help="Display what changes will be made without making any changes")
    all_parser.add_argument("--restart_apache", action="store_true", help="Restart Apache server without prompting")
    all_parser.add_argument("--verbose", action="store_true", help="Display verbose output")
    all_parser.set_defaults(func=do_everything)

    args = parser.parse_args()

    try:
        print ''
        LOGGER.info('DigiCert Express Install Config')
        print ''
        verify_requirements()
        args.func(args)
    except Exception, e:
        LOGGER.error(e)
        print ''


def restart_apache(args):
    express_utils.restart_apache(args.domain, args.verbose)


def configure_apache(args):
    domain = args.domain
    cert = args.cert
    chain = args.chain
    key = args.key

    if not domain:
        order = express_client.select_from_orders()
        if order:
            domain = order['certificate']['common_name']
            common_name = domain
    else:
        order = express_client.get_order_by_domain(domain)
        if order:
            common_name = order['certificate']['common_name']

    LOGGER.info("Updating the Apache configuration with SSL settings.")

    if not cert:
        cert = parsers.locate_cfg_file('%s.crt' % common_name.replace('.', '_'), 'Certificate',
                                       default_search_path="{0}/{1}".format(CFG_PATH, domain.replace('.', '_')))
        if not cert:
            LOGGER.error('No valid certificate file located; aborting.')
            return

    if not chain:
        chain = parsers.locate_cfg_file(['DigiCertCA.crt'], 'Certificate chain',
                                        default_search_path="{0}/{1}".format(CFG_PATH, domain.replace('.', '_')))
        if not chain:
            LOGGER.error('No valid certificate chain file located; aborting.')
            return

    if not key:
        key = parsers.locate_cfg_file('%s.key' % common_name.replace('.', '_'), 'Private key', validate_key=True,
                                      cert=cert,
                                      default_search_path="{0}/{1}".format(CFG_PATH, domain.replace('.', '_')))
        if not key:
            LOGGER.error('No valid private key file located; aborting.')
            return

    parsers.configure_apache(domain, cert, key, chain, apache_config=args.apache_config, dry_run=args.dry_run)

    if not args.dry_run:
        LOGGER.info('Please restart Apache for your changes to take effect.')


def download_cert(args):
    print args
    api_key = args.api_key

    order_id = args.order_id
    domain = args.domain

    order = None
    if not order_id and not domain:
        order = express_client.select_from_orders()

    if not order_id and domain:
        order = express_client.get_order_by_domain(domain)

    if order:
        order_id = order['id']
        domain = order['certificate']['common_name']

    express_client.download_cert(order_id, CFG_PATH, domain, api_key=api_key)


def do_everything(args):
    print args
    api_key = args.api_key

    # check the dependencies
    check_for_deps(args)

    order_id = args.order_id
    domain = args.domain
    key = args.key
    create_csr = args.create_csr
    dry_run = args.dry_run
    restart_web_server = args.restart_apache
    verbose = args.verbose

    do_everything_with_args(api_key=api_key, order_id=order_id, domain=domain, key=key, create_csr=create_csr,
                            dry_run=dry_run, restart_apache=restart_web_server, verbose=verbose)


def do_everything_with_args(api_key='', order_id='', domain='', key='', create_csr='', dry_run='', restart_apache='', verbose=''):
    # in some cases (*.domain.com, www.domain.com) the entered domain name could be slightly different
    # than the common name on the certificate, this really only matters when downloading the cert

    order_id, domain, common_name = express_client.get_order_and_domain_info(order_id, domain)

    if order_id:  #and not domain:
        # get the order info if the domain was not passed in the args
        LOGGER.info("Querying for issued certificates with order_id %s" % order_id)
        order_info = express_client.get_order_info(order_id)
        api_key = order_info.get('api_key', '')
        certificate = order_info.get('certificate', None)
        if certificate:
            domain = certificate.get('common_name', '')
            common_name = domain

        if create_csr:
            csr_response = express_utils.create_csr(common_name)
            if csr_response:
                key = csr_response.get('key')
                csr = csr_response.get('csr')

            # upload the csr
            if not express_client.upload_csr(order_id, csr, api_key=api_key):
                LOGGER.error("We could not upload your csr file, please try again or contact DigiCert support.")
                return

        cert = None
        chain = None
        if not create_csr:
            # if we didn't create the csr for them previously, their chain and cert could be on the filesystem
            # attempt to locate the cert and chain files
            # FIXME should we prompt the user to input the path to their files at this point?
            cert = parsers.locate_cfg_file('%s.crt' % common_name.replace('.', '_'), 'Certificate', prompt=False,
                                           default_search_path="{0}/{1}".format(CFG_PATH, domain.replace('.', '_')))
            chain = parsers.locate_cfg_file(['DigiCertCA.crt'], 'Certificate chain', prompt=False,
                                            default_search_path="{0}/{1}".format(CFG_PATH, domain.replace('.', '_')))

        # if we still don't have the cert and chain files, download them
        if not cert or not chain:
            certs = express_client.download_cert(order_id, CFG_PATH, common_name, api_key=api_key)
            chain = certs.get('chain', None)
            cert = certs.get('cert', None)

        if not key:
            key = parsers.locate_cfg_file('%s.key' % common_name.replace('.', '_'), 'Private key', validate_key=True,
                                          cert=cert,
                                          default_search_path="{0}/{1}".format(CFG_PATH, domain.replace('.', '_')))

        if not key:
            LOGGER.error('No valid private key file located; aborting.')
            return

        if order_info.get('product').get('name_id') == 'ssl_plus':
            LOGGER.info("Found product SSL PLUS Certificate, making changes")
            # make the changes to apache
            parsers.configure_apache(domain, cert, key, chain, dry_run=dry_run)
        else:
            # what about www domain and non www.? should www be removed?????
            # display to the user a prompt showing which domains are covered by their cert that are on the server
            # product = ssl_wildcard
            LOGGER.info("Product: %s" % order_info.get('product').get('name_id'))
            LOGGER.info("Found Non-SSL Plus product, making changes")

            # get all virtual hosts
            apache_parser = parsers.prepare_parser(domain, cert, key, chain, dry_run=dry_run)
            virtual_hosts = apache_parser.get_vhosts_on_server()
            # virtual_hosts = parsers.prepare_parser(domain, cert, key, chain, dry_run=dry_run)

            # get domains from the order
            domains = order_info.get('certificate').get('dns_names')

            # find matches from virtuals hosts and domains
            matched_hosts = parsers.compare_match(virtual_hosts, domains)

            if not matched_hosts:
                raise Exception("Didn't find any hosts matching SANS on this certificate")

            # prepare menu selection for the user to choose which virtual hosts to configure
            choices = zip(range(1, len(matched_hosts)+1), matched_hosts)
            doc_hosts = list()
            for choice in choices:
                s = [str(a) for a in choice]
                doc_hosts.append(". ".join(s))
            prompt_hosts = "\n".join(doc_hosts)
            LOGGER.info("The following virtual hosts on this server match the certificate. ")
            LOGGER.info(prompt_hosts)
            selected = raw_input("Choose which hosts to configure:\n\n")

            # from user input, determine the domains chosen.
            selection = selected.split(',')
            selected_hosts = []
            for x in selection:
                for choice in choices:
                    if int(x) == choice[0]:
                        LOGGER.info("User selected host: %s" % choice[1])
                        selected_hosts.append(choice[1])

            # finally, configure apache
            for s in selected_hosts:
                parsers.configure_apache(s, cert, key, chain, apache_parser=apache_parser, dry_run=dry_run)

        if not dry_run:
            if restart_apache or raw_input('Would you like to restart Apache now? (Y/n) ') != 'n':
                express_utils.restart_apache(domain, verbose)
                LOGGER.info("Congratulations, you've successfully installed your certificate to (%s)." % domain)
            else:
                LOGGER.info('Restart your Apache server for your changes to take effect.')
                LOGGER.info('Use the following command to restart your Apache server and verify your SSL settings:')
                LOGGER.info('sudo express_install restart_apache --domain "{0}"'.format(domain))
    else:
        LOGGER.error("ERROR: You must specify a valid domain or order id")


def verify_requirements():
    LOGGER.info("Verifying minimum requirements are met. ")
    os_name, os_version, code_name = express_utils.determine_platform()
    python_version = express_utils.determine_python_version()
    apache_version = express_utils.determine_apache_version(os_name)

    errors = []
    if apache_version:
        # TODO: could this be made simpler and more robust?
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
        express_utils.check_for_deps_centos(args.verbose)
    else:
        express_utils.check_for_deps_ubuntu(args.verbose)


if __name__ == '__main__':
    try:
        # run()
        do_everything_with_args(order_id='00687308', domain='nocsr.com', create_csr=True)
        print 'Finished'
    except KeyboardInterrupt:
        print
