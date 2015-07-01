import os

import express_utils

from express_utils import LOGGER
from express_utils import CFG_PATH
from parsers.base import BaseParser


def configure_apache(host, cert, key, chain, apache_parser=None, apache_config=None, is_multidomain=False):
    """
    Main method to configure a web server.
    :param host:  domain name to secure
    :param cert: path to cert file used to secure the web server
    :param key: path to key file to secure the web server
    :param chain: path to certificate chain file for securing the web server
    :param apache_parser: base parser object
    :param apache_config: path to apache config file
    :return:
    """

    LOGGER.info("Configuring Web Server for virtual host: %s" % host)
    if not apache_parser:
        apache_parser = BaseParser(host, cert, key, chain, CFG_PATH, is_multidomain=is_multidomain)
        apache_parser.load_apache_configs(apache_config)

    virtual_host = apache_parser.get_vhost_path_by_domain()
    apache_parser.set_certificate_directives(virtual_host)
    express_utils.enable_ssl_mod()

    LOGGER.info('Apache configuration updated successfully.')


def prepare_parser(host, cert, key, chain, apache_config=None):
    """
    :param host:
    :param cert:
    :param key:
    :param chain:
    :param apache_config:
    :return:
    """
    apache_parser = BaseParser(host, cert, key, chain, CFG_PATH)
    apache_parser.load_apache_configs(apache_config)
    return apache_parser


def locate_cfg_file(cfg_file_names, file_type, prompt=True, validate_key=False, cert=None, default_search_path=CFG_PATH):
    """
    :param cfg_file_names: list of file names to loop through
    :param file_type:
    :param prompt: boolean, set to true and will ask user for a path to the file
    :param validate_key:
    :param cert:
    :param default_search_path:
    :return:
    """

    LOGGER.info("Looking for {0}...".format(file_type))
    if isinstance(cfg_file_names, basestring):
        names = [cfg_file_names]
    else:
        names = cfg_file_names
    for cfg_file_name in names:
        file_path = os.path.join(default_search_path, cfg_file_name)
        if os.path.exists(file_path):
            return_file = True
            if validate_key:
                if not cert or not express_utils.validate_key(file_path, cert):
                    return_file = False
            if return_file:
                return file_path

    # Search the filesystem
    for cfg_file_name in names:
        sudo_user_name = os.getenv("SUDO_USER")
        sudo_user_home = "%s/%s" % ("/home", sudo_user_name)

        command = "find {0} -type f -name {1}".format(sudo_user_home, cfg_file_name)
        files = os.popen(command).read().splitlines()

        if len(files) > 0:
            matching_files = list()
            for file in files:
                if validate_key:
                    if cert and express_utils.validate_key(file, cert):
                        matching_files.append(file)
                else:
                    matching_files.append(file)

            if len(matching_files) == 1:
                return matching_files[0]
            elif len(matching_files) > 1:
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
                                raise ValueError
                        except ValueError as e:
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
                    answer = raw_input("Do you have a private key for the certificate you want to install? [y/n]  ")
                    if answer and answer.strip().lower() == 'y':
                        file_path = raw_input('Please provide a full absolute path to the file: ')
                    else:
                        file_path = 'q'
                        return ''

                    if os.path.exists(file_path):
                        if validate_key and cert:
                            if not express_utils.validate_key(file_path, cert):
                                raise Exception(
                                    "This key ({0}) does not match your certificate ({1}), please try again.".format(
                                        file_path, cert))
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


def compare_match(server_names, certificate_sans):
    """
    Compares if the certificate would secure this domain
    :param server_names: list of ServerName values
    :param certificate_sans: list of SAN's that would be secured by the certificate
    :return:
    """
    matches = []
    for server_name in server_names:
        # exception use case: sn: "www.test.fr"  san: "*.test.de, *.test.fr"
        for certificate_san in certificate_sans:
            sans = []
            if ',' in certificate_san:
                sans.extend(certificate_san.split(','))
            else:
                sans.append(certificate_san)

            # exception use case: sn: "FEDC:ba98:7654:3210:FEDC:BA98:7654:3210"  san: "FEDC:BA98:7654:3210:FEDC:ba98:7654:3210"
            if ':' in server_name and ':' in certificate_san:
                if server_name == certificate_san:
                    matches.append(server_name)
                else:
                    continue

            for san in sans:
                server_name = server_name.strip().lower()
                san = san.strip().lower()

                server_name_split = server_name.split('.')
                san_split = san.split('.')

                server_name_level = len(server_name_split)
                san_level = len(san_split)

                server_name_base = ".".join(server_name_split[-server_name_level+1:])
                san_base = ".".join(san_split[-san_level+1:])

                if server_name == san:
                    if server_name not in matches:
                        matches.append(server_name)
                if server_name_level == san_level:
                    if san_split[0] == '*' and (server_name_base == san_base):
                        if server_name not in matches:
                            matches.append(server_name)

    return matches