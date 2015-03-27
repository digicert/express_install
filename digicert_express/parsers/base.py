import augeas
import os
import shutil
import re
import fnmatch
import platform
from collections import OrderedDict

# FIXME check these commands on each platform
APACHE_SERVICES = {
    'LinuxMint': 'apache2',
    'CentOS': 'httpd',
    'Debian': 'apache2',
    'Ubuntu': 'apache2ctl'
}


class ParserException(Exception):
    def __init__(self, message, directives=None):
        self.message = "ERROR: {0}".format(message)
        if directives:
            self.message = "{0}\n\nYou may need to manually add/modify the following directives:\n".format(self.message)
            for directive in directives:
                self.message = "{0}\t{1} {2}\n".format(self.message, directive, directives[directive])


class BaseParser(object):
    """docstring for BaseParser"""

    def __init__(self, domain, cert_path, key_path, chain_path, storage_path='/etc/digicert', verbose=False, aug=None, dry_run=False):
        self.domain = domain
        self.dry_run = dry_run

        if not domain:
            raise ParserException("You need to specify a domain name to secure")

        if self.dry_run:
            self.lines = list()

        # get the apache service user
        command = "ps aux | egrep '(apache2|httpd)' | grep -v `whoami` | grep -v root | head -n1 | awk '{print $1}'"
        apache_user = os.popen(command).read()
        apache_user = apache_user.strip()

        # verify that the files exist and are readable by the user
        cert_path = verify_and_normalize_file(cert_path, "Certificate file", domain.replace(".", "_") + ".crt",
                                              apache_user, storage_path, verbose, dry_run)
        chain_path = verify_and_normalize_file(chain_path, "CA Chain file", domain.replace(".", "_") + ".pem",
                                               apache_user, storage_path, verbose, dry_run)
        key_path = verify_and_normalize_file(key_path, "Key file", domain.replace(".", "_") + ".key",
                                             apache_user, storage_path, verbose, dry_run)

        self.directives = OrderedDict()
        self.directives['SSLEngine'] = "on"
        self.directives['SSLCertificateFile'] = cert_path
        self.directives['SSLCertificateKeyFile'] = key_path
        self.directives['SSLCertificateChainFile'] = chain_path

        if not aug:
            my_flags = augeas.Augeas.NONE | augeas.Augeas.NO_MODL_AUTOLOAD
            aug = augeas.Augeas(flags=my_flags)
        self.aug = aug

    def load_apache_configs(self, apache_config_file=None):
        try:
            if not apache_config_file:
                apache_config_file = self._find_apache_config()

            self.aug.set("/augeas/load/Httpd/lens", "Httpd.lns")
            if apache_config_file:
                self.aug.set("/augeas/load/Httpd/incl", apache_config_file)
                self.aug.load()

                # get all of the included configuration files and add them to augeas
                self._load_included_files(apache_config_file)
                self.check_for_parsing_errors()
            else:
                raise Exception("We could not find your main apache configuration file.  Please ensure that apache is "
                                "running or include the path to your virtual host file in your command line arguments")
        except Exception, e:
            self.check_for_parsing_errors()
            raise ParserException(
                "An error occurred while loading your apache configuration.\n{1}".format(e.message),
                self.directives)

    @staticmethod
    def _find_apache_config():
        # FIXME this was stolen from main.py we should consider centralizing main.py's determine_platform() function
        distro = platform.linux_distribution()
        apache_command = "`which {0}` -V".format(APACHE_SERVICES.get(distro[0]))
        apache_config = os.popen(apache_command).read()
        if apache_config:
            server_config_check = "SERVER_CONFIG_FILE="
            httpd_root_check = "HTTPD_ROOT="

            server_config_file = apache_config[apache_config.index(server_config_check) + len(server_config_check): -1]
            server_config_file = server_config_file.replace('"', '')

            if server_config_file[0] != "/":
                # get the httpd root to find the server config file path
                httpd_root_dir = apache_config[apache_config.index(httpd_root_check) + len(httpd_root_check): -1]
                httpd_root_dir = httpd_root_dir[:httpd_root_dir.index("\n")]
                httpd_root_dir = httpd_root_dir.replace('"', '')

                if os.path.exists(httpd_root_dir) and os.path.isdir(httpd_root_dir):
                    server_config_file = os.path.join(httpd_root_dir, server_config_file)

            if os.path.exists(server_config_file):
                return server_config_file

    def _load_included_files(self, apache_config):
        # get the augeas path to the config file
        apache_config = "/files{0}".format(apache_config)

        incl_regex = "({0})|({1})".format(create_regex('Include'), create_regex('IncludeOptional'))
        includes = self.aug.match(("{0}//* [self::directive=~regexp('{1}')]/* [label()='arg']".format(apache_config, incl_regex)))

        if includes:
            for include in includes:
                include_file = self.aug.get(include)

                if include_file:
                    if include_file[0] != "/":
                        include_file = os.path.join(os.path.dirname(apache_config[6:]), include_file)

                    if "*" not in include_file and include_file[-1] != "/":
                        self.aug.set("/augeas/load/Httpd/incl [last()+1]", include_file)
                        self.aug.load()
                        self._load_included_files(include_file)
                    else:
                        if include_file[-1] == "/":
                            include_file += "*"
                        if "*" in include_file:
                            config_dir = os.path.dirname(include_file)
                            file_exp = include_file[include_file.index(config_dir) + len(config_dir) + 1:]
                            for file in os.listdir(config_dir):
                                if fnmatch.fnmatch(file, file_exp):
                                    config_file = os.path.join(config_dir, file)
                                    self.aug.set("/augeas/load/Httpd/incl [last()+1]", config_file)
                                    self.aug.load()
                                    self._load_included_files(config_file)

    def check_for_parsing_errors(self):
        errors = []
        error_files = self.aug.match("/augeas//error")
        for path in error_files:
            # check to see if it was an error resulting from the use of the httpd lens
            lens_path = self.aug.get(path + "/lens")
            if lens_path and "httpd.aug" in lens_path:
                # strip off /augeas/files and /error
                errors.append("Error parsing the file: {0} {1}".format(
                    path[13:len(path) - 6], self.aug.get(path + "/message")))

        if len(errors) > 0:
            error_msg = "The following errors occurred while parsing your configuration file:"
            for error in errors:
                error_msg = "{0}\t{1}\n".format(error_msg, error)
            raise Exception(error_msg)

    def get_vhost_path_by_domain(self):
        matches = self.aug.match("/augeas/load/Httpd/incl")
        for match in matches:
            host_file = "/files{0}".format(self.aug.get(match))
            if '~previous' not in host_file:
                vhosts = self.aug.match("{0}/*[label()=~regexp('{1}')]".format(host_file, create_regex("VirtualHost")))
                vhosts += self.aug.match("{0}/*/*[label()=~regexp('{1}')]".format(host_file, create_regex("VirtualHost")))

                vhost = self._get_vhost_path_by_domain_and_port(vhosts, '443')
                if not vhost:
                    vhost = self._get_vhost_path_by_domain_and_port(vhosts, '80')

                    if vhost:
                        # we didn't find an existing 443 virtual host but found one on 80
                        # create a new virtual host for 443 based on 80
                        vhost = self._create_secure_vhost(vhost)

                # return as soon as we have a vhost
                if vhost:
                    if self.dry_run:
                        self.lines = ["\nThe following changes will be made to "
                                      "{0}\n".format(get_path_to_file(vhost))] + self.lines
                    return vhost

    def _get_vhost_path_by_domain_and_port(self, vhosts, port):
        for vhost in vhosts:
            if port in self.aug.get(vhost + "/arg"):
                check_matches = self.aug.match("{0}/*[self::directive=~regexp('{1}')]".format(vhost, create_regex("ServerName")))
                if check_matches:
                    for check in check_matches:
                        if self.aug.get(check + "/arg"):
                            aug_domain = self.aug.get(check + "/arg")
                            if aug_domain == self.domain:
                                return vhost
                            if self.domain.startswith('www.'):
                                if self.domain.split('.', 1)[1] == aug_domain:
                                    return vhost
                            else:
                                if aug_domain == 'www.%s' % self.domain:
                                    return vhost

    def _create_secure_vhost(self, vhost):
        secure_vhost = None
        host_file = "/files{0}".format(get_path_to_file(vhost))

        # create a map of the insecure vhost's configuration
        vhost_map = list()
        self._create_map_from_vhost(vhost, vhost_map)

        # check if there is an IfModule for mod_ssl.c, if not create it
        if_module = None
        check_matches = self.aug.match("{0}/*[label()=~regexp('{1}')]".format(host_file, create_regex("IfModule")))
        if check_matches:
            for check in check_matches:
                if self.aug.get(check + "/arg") == "mod_ssl.c":
                    if_module = check

        if self.dry_run:
            terminate_if_module = False
            self.lines.append("The following Virtual Host will be created:\n")
        if not if_module:
            self.aug.set(host_file + "/IfModule[last()+1]/arg", "mod_ssl.c")
            if self.dry_run:
                self.lines.append("<IfModule mod_ssl.c>")
                terminate_if_module = True
            if_modules = self.aug.match(host_file + "/*[self::IfModule/arg='mod_ssl.c']")
            if len(if_modules) > 0:
                if_module = if_modules[0]
            else:
                raise ParserException(
                    "An error occurred while creating IfModule mod_ssl.c for {0}.".format(self.domain), self.directives)

        # create a new secure vhost
        vhost_name = self.aug.get(vhost + "/arg")
        vhost_name = vhost_name[0:vhost_name.index(":")] + ":443"
        self.aug.set(if_module + "/VirtualHost[last()+1]/arg", vhost_name)
        if self.dry_run:
            self.lines.append("<VirtualHost {0}>".format(vhost_name))

        vhosts = self.aug.match("{0}/*[self::VirtualHost/arg='{1}']".format(if_module, vhost_name))
        for vhost in vhosts:
            secure_vhost = vhost

            # write the insecure vhost configuration into the new secure vhost
            self._create_vhost_from_map(secure_vhost, vhost_map)

        if self.dry_run:
            # terminate the VirtualHost and IfModule
            self.lines.append("</VirtualHost>")
            if terminate_if_module:
                self.lines.append("</IfModule>")
        self.check_for_parsing_errors()

        return secure_vhost

    def _create_map_from_vhost(self, path, vhost_map, text=""):
        # recurse through the directives and sub-groups to generate a map
        check_matches = self.aug.match(path + "/*")
        if check_matches:
            for check in check_matches:
                values = list()
                # get the type of configuration
                config_type = check[len(path)+1:]
                config_name = self.aug.get(check)
                config_value = self.aug.get(check + "/arg")

                if "arg" not in config_type and "#comment" not in config_type:
                    # check if we have a config_value, if we don't its likely that there are multiple
                    # values rather than just one and we need to get them via aug.match
                    if not config_value:
                        arg_check_matches = self.aug.match("{0}/{1}/arg".format(path, config_type))
                        for arg_check in arg_check_matches:
                            values.append(self.aug.get(arg_check))
                            if config_value:
                                config_value += " {0}".format(self.aug.get(arg_check))
                            else:
                                config_value = self.aug.get(arg_check)
                    else:
                        values.append(config_value)

                    # check for config_name, if we don't then this a sub-group and not a directive
                    if not config_name:
                        # this is a sub-group, recurse
                        sub_map = list()
                        vhost_map.append({'type': config_type, 'name': None, 'values': values, 'sub_group': sub_map})
                        self._create_map_from_vhost(path + "/" + config_type, sub_map, "{0}\t".format(text))
                    else:
                        vhost_map.append({'type': config_type, 'name': config_name, 'values': values, 'sub_group': None})

    def _create_vhost_from_map(self, path, vhost_map, text=""):
        # recurse through the map and write the new vhost
        for entry in vhost_map:
            config_type = entry['type']
            config_name = entry['name']
            config_values = entry['values']
            config_sub = entry['sub_group']

            value = None
            for v in config_values:
                if not value:
                    value = v
                else:
                    value += " {0}".format(v)

            self.aug.set("{0}/{1}".format(path, config_type), config_name)
            if self.dry_run:
                if not config_name:
                    if '[' in config_type:
                        line = "<{0}".format(config_type[0:config_type.index('[')])
                    else:
                        line = "<{0}".format(config_type)
                else:
                    line = config_name
            if len(config_values) > 1:
                i = 1
                for value in config_values:
                    self.aug.set("{0}/{1}/arg[{2}]".format(path, config_type, i), value)
                    if self.dry_run:
                        line = "{0} {1}".format(line, value)
                    i += 1
            else:
                self.aug.set("{0}/{1}/arg".format(path, config_type), value)
                if self.dry_run:
                    line = "{0} {1}".format(line, value)

            if self.dry_run:
                if not config_name:
                    line += ">"

                self.lines.append(line)

            if not config_name and config_type and config_sub:
                # this is a sub-group, recurse
                sub_groups = self.aug.match("{0}/{1}".format(path, config_type))
                for sub_group in sub_groups:
                    self._create_vhost_from_map(sub_group, config_sub, "{0}\t".format(text))
                    if self.dry_run:
                        if '[' in config_type:
                            self.lines.append("</{0}>".format(config_type[0:config_type.index('[')]))
                        else:
                            self.lines.append("</{0}>".format(config_type))

    def set_certificate_directives(self, vhost_path):
        try:
            if not vhost_path:
                raise Exception("Virtual Host was not found for {0}".format(self.domain))

            # back up the configuration file
            host_file = get_path_to_file(vhost_path)
            shutil.copy(host_file, "{0}~previous".format(host_file))

            errors = []
            if self.dry_run:
                self.lines.append("\nThe following security directives will be added/modified to your secure virtual host:\n")
            for directive in self.directives:
                matches = self.aug.match("{0}/*[self::directive=~regexp('{1}')]".format(vhost_path, create_regex(directive)))
                if len(matches) > 0:
                    for match in matches:
                        self.aug.set("{0}/arg".format(match), self.directives[directive])
                        if self.dry_run:
                            self.lines.append("{0} {1} #updated value".format(directive, self.directives[directive]))
                else:
                    self.aug.set(vhost_path + "/directive[last()+1]", directive)
                    self.aug.set(vhost_path + "/directive[last()]/arg", self.directives[directive])
                    if self.dry_run:
                        self.lines.append("{0} {1} #added".format(directive, self.directives[directive]))
            if self.dry_run:
                self.lines.append("")

            if len(errors):
                error_msg = "Could not update all directives:\n"
                for error in errors:
                    error_msg = "{0}\t{1}\n".format(error_msg, error)
                raise Exception(error_msg)

            if not self.dry_run:
                self.aug.save()

            # check for augeas errors
            self.check_for_parsing_errors()

            # verify the added/modified directives are the values we set
            errors = []
            for directive in self.directives:
                val = None
                matches = self.aug.match("{0}/*[self::directive=~regexp('{1}')]/arg".format(vhost_path, create_regex(directive)))
                if len(matches) > 0:
                    for match in matches:
                        val = self.aug.get(match)

                if val != self.directives[directive]:
                    errors.append("{0} is {1} instead of {2}".format(directive, val, self.directives[directive]))

            if len(errors) > 0:
                error_msg = "Some of your directives are incorrect:\n"
                for error in errors:
                    error_msg = "{0}\t{1}\n".format(error_msg, error)
                raise Exception(error_msg)

        except Exception, e:
            self.check_for_parsing_errors()
            raise ParserException(
                "An error occurred while updating the Virtual Host for {0}.\n{1}".format(self.domain, e.message),
                self.directives)

        # format the file:
        try:
            if self.dry_run:
                format_dry_run(self.lines)
            else:
                format_config_file(host_file)
        except Exception, e:
            raise Exception("The changes have been made but there was an error occurred while formatting "
                            "your file:\n{0}".format(e.message))

        if not self.dry_run:
            # verify that augeas can still load the changed file
            self.aug.load()


def verify_and_normalize_file(file_path, desc, name, apache_user, storage_path, verbose=False, dry_run=False):

    """
    Verify that the file exists, move it to a common location, & set the proper permissions

    :param file_path  the file to verify/normalize
    :param desc  what kind of file is this? for output purposes only
    :param name what the new file name should be
    :param apache_user  the user apache runs as
    :param storage_path  where to store the file
    :param verbose  whether or not to print more output
    :return:
    """

    if not os.path.isfile(file_path):
        raise ParserException("{0} '{1}' could not be found on the filesystem".format(desc, file_path))

    if not os.path.exists(storage_path):
        os.mkdir(storage_path)

    # copy the files to the storage path if they aren't already there
    path = os.path.dirname(file_path)
    old_name = os.path.basename(file_path)
    if storage_path != path or old_name != name:
        normalized_cfg_file = '%s/%s' % (storage_path, name)
        if not dry_run:
            shutil.copy(file_path, normalized_cfg_file)
            if verbose:
                print 'Copied %s to %s...' % (file_path, normalized_cfg_file)
        file_path = normalized_cfg_file

    # change the owners of the ssl files
    os.system("chown root:{0} {1}".format(apache_user, file_path))

    # change the permission of the ssl files, only the root and apache users should have read permissions
    os.system("chmod 640 {0}".format(file_path))

    return file_path


def get_path_to_file(path):
    """
    Take an augeas path (ie: /files/etc/apache2/apache2.conf/VirtualHost/Directory/) and return the path
    to the apache configuration file (ie: /etc/apache2/apache2.conf)

    :param path
    :return: path to an actual file or None
    """

    if "/files/" in path[:7]:
        path = path[6:]

    while not os.path.exists(path) and not os.path.isdir(path):
        last_slash_index = path.rfind("/")
        if last_slash_index > 0:
            path = path[:last_slash_index]
        else:
            return None
    return path


def create_regex(text):
    """
    Escape and return the passed string in upper and lower case to match regardless of case.
    Augeas 1.0 supports the standard regex /i but previous versions do not.  Also, not all (but most) unix/linux
    platforms support /i.  So this is the safest method to ensure matches.

    :param text: string to create regex from
    :return: regex
    """

    return "".join(["[" + c.upper() + c.lower() + "]" if c.isalpha() else c for c in re.escape(text)])


def format_config_file(host_file):
    """
    Format the apache configuration file.  Loop through the lines of the file and indent/un-indent where necessary

    :param host_file:
    :return:
    """

    # get the lines of the config file
    lines = list()
    with open(host_file) as f:
        lines = f.read().splitlines()

    f = open(host_file, 'w+')

    try:
        format_lines(lines, f)
    finally:
        f.truncate()
        f.close()


def format_dry_run(lines):
    """
    Format the changes that were going to be made to the apache configuration file.
    Loop through the lines of the file and indent/un-indent where necessary

    :param lines:
    :return:
    """
    import sys
    format_lines(lines, sys.stdout)


def format_lines(lines, f):
    tabs = ""
    for line in lines:
        line = line.lstrip()
        # check for the beginning of a tag, if found increase the indentation after writing the tag
        if re.match("^<(\w+)", line):
            f.write("{0}{1}\n".format(tabs, line))
            tabs += "\t"
        else:
            # check for the end of a tag, if found decrease the indentation
            if re.match("^</(\w+)", line):
                if len(tabs) > 1:
                    tabs = tabs[:-1]
                else:
                    tabs = ""
            # write the config/tag
            f.write("{0}{1}\n".format(tabs, line))
