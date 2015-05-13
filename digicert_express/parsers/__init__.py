import os
import express_utils

from express_utils import LOGGER
from express_utils import CFG_PATH
from parsers.base import BaseParser


def configure_apache(host, cert, key, chain, apache_config=None, dry_run=False):
    LOGGER.info('Parsing Apache configuration for virtual hosts...')
    apache_parser = BaseParser(host, cert, key, chain, CFG_PATH, logger=LOGGER, dry_run=dry_run)
    apache_parser.load_apache_configs(apache_config)
    virtual_host = apache_parser.get_vhost_path_by_domain()

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

    LOGGER.info('adding certificate directives for host: %s...' % log_virtual_host)
    apache_parser.set_certificate_directives(virtual_host)

    LOGGER.info('enabling Apache SSL module for host: %s' % log_virtual_host)
    express_utils.enable_ssl_mod()

    if not dry_run:
        LOGGER.info('Apache configuration updated successfully.')
        print ''


def locate_cfg_file(cfg_file_names, file_type, prompt=True, validate_key=False, cert=None,
                    default_search_path=CFG_PATH):
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
        print sudo_user_name
        sudo_user_home = "%s/%s" % ("/home", sudo_user_name)
        print sudo_user_home
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
                    file_path = raw_input(
                        '%s file could not be found.  Please provide a path to the file: ' % file_type)
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