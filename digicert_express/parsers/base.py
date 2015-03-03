import augeas
import os
import shutil
import re
from collections import OrderedDict


class ParserException(Exception):
    def __init__(self, message, directives=None):
        self.message = "ERROR: {0}".format(message)
        if directives:
            self.message = "{0}\n\nYou may need to manually add/modify the following directives:\n".format(self.message)
            for directive in directives:
                self.message = "{0}\t{1} {2}\n".format(self.message, directive, directives[directive])


class BaseParser(object):
    """docstring for BaseParser"""

    def __init__(self, domain, cert_path, key_path, chain_path, aug=None):
        self.domain = domain

        # verify that the files exist and are readable by the user
        self._verify_file(cert_path)
        self._verify_file(key_path)
        self._verify_file(chain_path)

        self.directives = OrderedDict()
        self.directives['SSLEngine'] = "on"
        self.directives['SSLCertificateFile'] = cert_path
        self.directives['SSLCertificateKeyFile'] = key_path
        self.directives['SSLCertificateChainFile'] = chain_path

        if not aug:
            my_flags = augeas.Augeas.NONE | augeas.Augeas.NO_MODL_AUTOLOAD
            aug = augeas.Augeas()  # flags=my_flags)
        self.aug = aug

    @staticmethod
    def _verify_file(file_path):
        if not os.path.isfile(file_path):
            raise ParserException("{0} could not be found on the filesystem".format(file_path))

        file_perm = int(oct(os.stat(file_path).st_mode)[-3:])
        if file_perm != 755:
            raise ParserException("{0} does not have the necessary permissions set (755 required, {1} set)".format(file_path, file_perm))

    def load_apache_configs(self):
        try:
            self.aug.set("/augeas/load/Httpd/lens", "Httpd.lns")
            # FIXME this should be determined by the platform or webserver specific parsing settings and is norammly done automatically by augeas
            # self.aug.set("/augeas/load/Httpd/incl", "/etc/apache2/")
            self.aug.load()
            self.check_for_parsing_errors()
        except Exception, e:
            raise ParserException(
                "An error occurred while loading the configuration for {0}.\n{1}".format(self.domain, e.message),
                self.directives)

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
        matches = self.aug.match("/files/etc/apache2/sites-available/*")
        for host_file in matches:
            if '~previous' not in host_file:
                vhosts = self.aug.match(host_file + "/VirtualHost")
                vhosts += self.aug.match(host_file + "/*/VirtualHost")

                vhost = self._get_vhost_path_by_domain_and_port(vhosts, '443')
                if not vhost:
                    vhost = self._get_vhost_path_by_domain_and_port(vhosts, '80')

                    if vhost:
                        # we didn't find an existing 443 virtual host but found one on 80
                        # create a new virtual host for 443 based on 80
                        vhost = self._create_secure_vhost(vhost)

                # return as soon as we have a vhost
                if vhost:
                    return vhost

    def _get_vhost_path_by_domain_and_port(self, vhosts, port):
        for vhost in vhosts:
            if port in self.aug.get(vhost + "/arg"):
                check_matches = self.aug.match(vhost + '/directive')
                if check_matches:
                    for check in check_matches:
                        if self.aug.get(check) == 'ServerName' and self.aug.get(check + "/arg") is not None \
                                and self.aug.get(check + "/arg") == self.domain:
                            return vhost
                else:
                    check_matches = self.aug.match(vhost + '/directive')
                    for check in check_matches:
                        if self.aug.get(check) == 'ServerName' and self.aug.get(check + "/arg") is not None \
                                and self.aug.get(check + "/arg") == self.domain:
                            return vhost

    def _create_secure_vhost(self, vhost):
        secure_vhost = None
        host_file = vhost[0:vhost.index("VirtualHost")-1]

        # create a map of the insecure vhost's configuration
        vhost_map = list()
        self._create_map_from_vhost(vhost, vhost_map)

        # check if there is an IfModule for mod_ssl.c, if not create it
        if_module = None
        check_matches = self.aug.match(host_file + "/IfModule")
        if check_matches:
            for check in check_matches:
                if self.aug.get(check + "/arg") == "mod_ssl.c":
                    if_module = check

        if not if_module:
            self.aug.set(host_file + "/IfModule[last()+1]/arg", "mod_ssl.c")
            if_modules = self.aug.match("{0}/*[self::IfModule/arg='mod_ssl.c']".format(host_file))
            if len(if_modules) > 0:
                if_module = if_modules[0]
            else:
                raise ParserException(
                    "An error occurred while creating IfModule mod_ssl.c for {0}.\n{1}".format(self.domain, e.message),
                    self.directives)

        # create a new secure vhost
        vhost_name = self.aug.get(vhost + "/arg")
        vhost_name = vhost_name[0:vhost_name.index(":")] + ":443"
        self.aug.set(if_module + "/VirtualHost[last()+1]/arg", vhost_name)
        vhosts = self.aug.match("{0}/IfModule/*[self::VirtualHost/arg='{1}']".format(host_file, vhost_name))
        for vhost in vhosts:
            secure_vhost = vhost

            # write the insecure vhost configuration into the new secure vhost
            self._create_vhost_from_map(secure_vhost, vhost_map)

        self.check_for_parsing_errors()

        return secure_vhost

    def _create_map_from_vhost(self, path, vhost_map, text=""):
        # recurse through the directives and sub-groups to generate a map
        check_matches = self.aug.match(path + '/*')
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
            if len(config_values) > 1:
                i = 1
                for value in config_values:
                    self.aug.set("{0}/{1}/arg[{2}]".format(path, config_type, i), value)
                    i += 1
            else:
                self.aug.set("{0}/{1}/arg".format(path, config_type), value)

            if not config_name and config_type and config_sub:
                # this is a sub-group, recurse
                sub_groups = self.aug.match("{0}/{1}".format(path, config_type))
                for sub_group in sub_groups:
                    self._create_vhost_from_map(sub_group, config_sub, "{0}\t".format(text))

    def set_certificate_directives(self, vhost_path):
        try:
            if not vhost_path:
                raise Exception("Virtual Host was not found for {0}".format(self.domain))

            # back up the configuration file
            host_file = vhost_path[6:vhost_path.index("IfModule")-1]
            shutil.copy(host_file, "{0}~previous".format(host_file))

            errors = []
            for directive in self.directives:
                val = self.aug.match("{0}/*[self::directive='{1}']".format(vhost_path, directive))
                if val:
                    self.aug.set("{0}/*[self::directive='{1}']/arg".format(vhost_path, directive), self.directives[directive])
                else:
                    self.aug.set(vhost_path + "/directive[last()+1]", directive)
                    self.aug.set(vhost_path + "/directive[last()]/arg", self.directives[directive])

            if len(errors):
                error_msg = "Could not update all directives:\n"
                for error in errors:
                    error_msg = "{0}\t{1}\n".format(error_msg, error)
                raise Exception(error_msg)

            self.aug.save()

            # check for augeas errors
            self.check_for_parsing_errors()

            # verify the added/modified directives are the values we set
            errors = []
            for directive in self.directives:
                val = self.aug.get("{0}/*[self::directive='{1}']/arg".format(vhost_path, directive))
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
        self._format_config_file(host_file)

        # verify that augeas can still load the changed file
        self.load_apache_configs()

    @staticmethod
    def _format_config_file(host_file):
        try:
            # get the lines of the config file
            lines = list()
            with open(host_file) as f:
                lines = f.read().splitlines()

            f = open(host_file, 'w+')

            try:
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
            finally:
                f.truncate()
                f.close()
        except Exception, e:
            raise Exception("The changes have been made but there was an error occurred while formatting your file:\n{0}".format(e.message))
