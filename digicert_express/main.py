import os
import argparse
import subprocess
from digicert_procure import CertificateOrder
import platform
import shutil
from parsers.base import BaseParser

APACHE_COMMANDS = {
    'LinuxMint': 'sudo service apache2 restart',
    'CentOS': 'sudo service httpd restart',
    'Debian': 'sudo /etc/init.d/apache2 restart',
    'Ubuntu': 'sudo service apache2 restart'
}


def run():
    parser = argparse.ArgumentParser(
        description='Express Install. Let DigiCert manage your certificates for you!',
        version='0.1 First pass')
    # parser.add_argument("-r", "--restart_apache", action="store_true", default=False, help="I'll restart the Apache web server for you")
    # parser.add_argument("-p", "--parse_apache", action="store_true", default=False, help="I'll parse the apache configuration and back it up to /tmp")
    # parser.add_argument("-s", "--ssl_apache", action="store_true", default=False, help="I'll update new config with the SSL configuation for a new certificate")
    # parser.add_argument("-u", "--update_apache", action="store_true", default=False, help="I'll save the newly updated SSL configuration to apache")

    subparsers = parser.add_subparsers(help='Choose a command')
    parser_a = subparsers.add_parser('restart_apache', help='restart apache')
    parser_a.set_defaults(func=restart_apache)


    parser_b = subparsers.add_parser('parse_apache', help='parse apache')
    parser_b.add_argument("--host", action="store",
                          help="I need a host to update")
    parser_b.add_argument("--cert", action="store",
                          help="I need the path to the cert for the configuration file")
    parser_b.add_argument("--key", action="store",
                          help="I need the path to the key for the configuration file")
    parser_b.add_argument("--chain", action="store",
                          help="I need the cert chain for the configuration file")
    parser_b.add_argument("--apache_config", action="store", default=None,
                          help="If you know the path your Virtual Host file or main Apache configuration file please "
                               "include it here, if not we will try to find it for you")
    parser_b.set_defaults(func=parse_apache)

    # TODO: commenting out for now, these may not be necessary
    # may not be a purpose for these commands
    # parser_c = subparsers.add_parser('ssl_apache', help='ssl apache')
    # parser_c.set_defaults(func=ssl_apache)
    #
    # parser_d = subparsers.add_parser('update_apache', help='update apache')
    # parser_d.set_defaults(func=update_apache)


    parser_e = subparsers.add_parser('download_cert',
                                     help='download certificate')
    parser_e.add_argument("--order_id", action="store",
                          help="I need an order_id")
    parser_e.add_argument("--api_key", action="store", help="I need an API Key")
    parser_e.add_argument("--account_id", nargs="?", action="store",
                          help="I need an account_id")
    parser_e.add_argument("--file_path", action="store", default=os.getcwd(),
                          help="Where should I store the cert?")
    parser_e.set_defaults(func=download_cert)


    parser_f = subparsers.add_parser('copy_cert', help='activate certificate')
    parser_f.add_argument("--cert_path", action="store",
                          help="Path to the cert")
    parser_f.add_argument("--apache_path", action="store",
                          help="Path to store the cert")
    parser_f.set_defaults(func=copy_cert)


    parser_g = subparsers.add_parser("all", help='Download and Configure cert in one step')
    parser_g.add_argument("--order_id", action="store",
                          help="I need an order_id")
    parser_g.add_argument("--api_key", action="store", help="I need an API Key")
    parser_g.add_argument("--account_id", nargs="?", action="store",
                          help="I need an account_id")
    parser_g.add_argument("--file_path", action="store", default=os.getcwd(),
                          help="Where should I store the cert?")
    parser_g.set_defaults(func=do_everything)

    args = parser.parse_args()
    print args

    args.func(args)
    print 'finished!'


def restart_apache(args):
    distro_name = determine_platform()
    command = APACHE_COMMANDS.get(distro_name)
    print subprocess.call(command, shell=True)
    print "my job is to restart the apache web server"


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


# TODO: commenting out for now, these may not be necessary
# def ssl_apache(args):
# print "my job is to update the ssl configuration at /tmp with the supplied certificate"
#
#
# def update_apache(args):
#     print "my job is to take the backuped up configuration in /tmp and overwrite the real apache configuration"


def download_cert(args):
    print "my job is to download the certificate from digicert.com using the digicert_client module with order_id %s and account_id %s" % (
        args.order_id, args.account_id)
    orderclient = CertificateOrder('www.digicert.com', args.api_key,
                                   customer_name=args.account_id)
    certificates = orderclient.download({'order_id': args.order_id})
    result_cert = certificates.get('certificates').get('certificate')
    file = open(args.file_path + '/cert.crt', 'w')
    file.write(result_cert)
    print result_cert


def copy_cert(args):
    print "my job is to copy the certificate from where it is downloaded to to where apache can read it"
    cert_path = args.cert_path
    apache_path = args.apache_path
    shutil.copyfile(cert_path, apache_path)


def do_everything(args):
    download_cert(args)
    parse_apache(args)
    copy_cert(args)
    restart_apache(args)


def determine_platform():
    # TODO: this should be made more robust after testing on each platform
    distro = platform.linux_distribution()  # returns a tuple ('', '', '') (distroName, version, code name)
    return distro[0]


if __name__ == '__main__':
    run()