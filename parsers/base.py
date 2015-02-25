import augeas
import os
import shutil
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

    def __init__(self, domain, cert_path, chain_path, aug=None):
        self.domain = domain

        # verify that the files exist and are readable by the user
        if not os.path.isfile(cert_path):
            raise ParserException("{0} could not be found on the filesystem".format(cert_path))

        if not os.path.isfile(chain_path):
            raise ParserException("{0} could not be found on the filesystem".format(chain_path))

        cert_path_perm = int(oct(os.stat(cert_path).st_mode)[-3:])
        if cert_path_perm != 755:
            raise ParserException("{0} does not have the necessary permissions set (755 required, {1} set)".format(cert_path, cert_path_perm))

        chain_path_perm = int(oct(os.stat(chain_path).st_mode)[-3:])
        if chain_path_perm != 755:
            raise ParserException("{0} does not have the necessary permissions set (755 required, {1} set)".format(chain_path, chain_path_perm))

        self.directives = OrderedDict()
        self.directives['SSLCertificateFile'] = cert_path
        self.directives['SSLCertificateChainFile'] = chain_path

        if not aug:
            my_flags = augeas.Augeas.NONE | augeas.Augeas.NO_MODL_AUTOLOAD
            aug = augeas.Augeas()  # flags=my_flags)
        self.aug = aug

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
                print host_file
                vhosts = self.aug.match(host_file + "/VirtualHost")
                if not vhosts:
                    vhosts = self.aug.match(host_file + "/*/VirtualHost")
                for vhost in vhosts:
                    print self.aug.get(vhost + "/arg")
                    if '443' in self.aug.get(vhost + "/arg"):
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

    def set_certificate_directives(self, vhost_path):
        try:

            if not vhost_path:
                raise Exception("Virtual Host was not found for {0}".format(self.domain))

            # back up the configutation file
            conf_file = vhost_path[6:vhost_path.index("IfModule")-1]
            shutil.copy(conf_file, "{0}~previous".format(conf_file))

            updates = 0
            errors = []
            for directive in self.directives:
                val = self.aug.match("{0}/*[self::directive='{1}']".format(vhost_path, directive))
                if val:
                    self.aug.set("{0}/*[self::directive='{1}']/arg".format(vhost_path, directive), self.directives[directive])
                    updates += 1
                else:
                    errors.append("Could not find " + directive)

            if len(errors) > 0 or updates < len(self.directives):
                error_msg = "Could not update all directives ({0}):\n".format(updates)
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
            raise ParserException(
                "An error occurred while updating the Virtual Host for {0}.\n{1}".format(self.domain, e.message),
                self.directives)
