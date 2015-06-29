import os

import express_utils

from express_utils import LOGGER
from express_utils import CFG_PATH
from parsers.base import BaseParser


def configure_apache(host, cert, key, chain, apache_parser=None, apache_config=None, dry_run=False):
    """
    Main method to configure a web server.
    :param host:  domain name to secure
    :param cert: path to cert file used to secure the web server
    :param key: path to key file to secure the web server
    :param chain: path to certificate chain file for securing the web server
    :param apache_parser: base parser object
    :param apache_config: path to apache config file
    :param dry_run:
    :return:
    """
    LOGGER.info('In configure apache, parsing Apache configuration for virtual hosts...')

    if not apache_parser:
        LOGGER.info("not apache parser")
        apache_parser = BaseParser(host, cert, key, chain, CFG_PATH, dry_run=dry_run)
        LOGGER.info("calling load apache configs()")
        apache_parser.load_apache_configs(apache_config)

    LOGGER.info("getting ready to call get_vhost_path_by_domain")
    virtual_host = apache_parser.get_vhost_path_by_domain()
    LOGGER.info("In Configure apache, virtual host: %s" % virtual_host)

    LOGGER.info('adding certificate directives for host: %s...' % host)
    apache_parser.set_certificate_directives(virtual_host)

    LOGGER.info('enabling Apache SSL module for host: %s' % host)
    express_utils.enable_ssl_mod()

    if not dry_run:
        LOGGER.info('Apache configuration updated successfully.')
        print ''


def prepare_parser(host, cert, key, chain, apache_config=None, dry_run=False):
    """
    :param host:
    :param cert:
    :param key:
    :param chain:
    :param apache_config:
    :param dry_run:
    :return:
    """
    LOGGER.info('Parsing Apache configuration for virtual hosts...')
    apache_parser = BaseParser(host, cert, key, chain, CFG_PATH, dry_run=dry_run)
    apache_parser.load_apache_configs(apache_config)
    return apache_parser


def _log_virtual_host(host, virtual_host):
    """
    method used for logging the virtual host to the log file
    :param host: domain to log
    :param virtual_host: augeas virtual host path
    :return:
    """
    # TODO: remove this hack for logging
    if virtual_host:
        begin_index = virtual_host.find('/etc')
        end_index = virtual_host.find('/VirtualHost')
        if begin_index and end_index:
            log_virtual_host = virtual_host[begin_index:end_index]
            LOGGER.info('found virtual host %s...' % log_virtual_host)
    else:
        log_virtual_host = 'cannot find virtual host'
        LOGGER.info('%s: %s' % (log_virtual_host, host))
        raise Exception("Virtual Host was not found for {0}.  Please verify that the 'ServerName' directive in "
                                "your Virtual Host is set to {1} and try again.".format(host, host))
    return log_virtual_host


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
    # TODO: break up this method??
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
                    file_path = raw_input(
                        '%s file could not be found.  Please provide a path to the file: \n Or "q" if you do not have a private key: ' % file_type)
                    if file_path:
                        if file_path.strip().lower() == 'q':
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