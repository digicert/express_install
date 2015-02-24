import augeas
from collections import OrderedDict


class ParserException(Exception):
    def __init__(self, message, directives):
        self.msg = "ERROR: {0}".format(message)
        if directives:
            self.msg = "{0}\n\nYou will need to manually add the following directives:\n".format(self.msg)
            for directive in directives:
                self.msg = "{0}\t{1} {2}\n".format(self.msg, directive, directives[directive])


class BaseParser(object):
    """docstring for BaseParser"""

    def __init__(self, domain, cert_path, chain_path, aug=None):
        self.domain = domain

        self.directives = OrderedDict()
        self.directives['SSLCertificateFile'] = cert_path
        self.directives['SSLCertificateChainFile'] = chain_path

        if not aug:
            my_flags = augeas.Augeas.NONE | augeas.Augeas.NO_MODL_AUTOLOAD
            aug = augeas.Augeas()  # flags=my_flags)
        self.aug = aug

    def load_apache_configs(self):
        self.aug.set("/augeas/load/Httpd/lens", "Httpd.lns")
        # FIXME this should be determined by the platform or webserver specific parsing settings and is norammly done automatically by augeas
        # self.aug.set("/augeas/load/Httpd/incl", "/etc/apache2/")
        self.aug.load()

    def get_vhost_path_by_domain(self):
        matches = self.aug.match("/files/etc/apache2/sites-available/*")
        for host_file in matches:
            vhosts = self.aug.match(host_file + "/VirtualHost")
            if not vhosts:
                vhosts = self.aug.match(host_file + "/*/VirtualHost")
            for vhost in vhosts:
                print self.aug.get(vhost + "/arg")
                if '443' in self.aug.get(vhost + "/arg"):
                    check_matches = self.aug.match(vhost + '/directive')
                    if check_matches:
                        for check in check_matches:
                            if self.aug.get(check) == 'ServerName' and self.aug.get(
                                            check + "/arg") != None and self.aug.get(check + "/arg") == self.domain:
                                return vhost
                    else:
                        check_matches = self.aug.match(vhost + '/directive')
                        for check in check_matches:
                            if self.aug.get(check) == 'ServerName' and self.aug.get(
                                            check + "/arg") != None and self.aug.get(check + "/arg") == self.domain:
                                return vhost

    def set_certificate_directives(self, vhost_path):
        if not vhost_path:
            raise ParserException("Virtual Host was not found for {0}".format(self.domain), self.directives)

        try:
            updates = 0
            for directive in self.directives:
                # FIXME this needs to look for and use existing existing directives in the passed vhost file
                val = self.aug.match("{0}/*[self::directive='{1}']".format(vhost_path, directive))
                if val:
                    self.aug.set("{0}/*[self::directive='{1}']/arg".format(vhost_path, directive), self.directives[directive])
                    update = update+1
            if updates < len(self.directives):
                raise Exception("could not update all directives ({0})".format(updates))
        except Exception as e:
            raise ParserException(
                "An error occurred while updating the Virtual Host for {0}.\n{1}".format(self.domain, e.message),
                self.directives)

        self.aug.save()
