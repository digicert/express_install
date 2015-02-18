from parsers.base import BaseParser

b = BaseParser()
b.load_apache_configs()
vhost = b.get_vhost_path_by_domain('localhost.digicert.com')
b.set_certificate_directives(vhost, '/a/b/c.pem', '/a/b/c.crt')