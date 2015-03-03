from parsers.base import BaseParser
b = BaseParser('crazyhost.digicert.com', '/a/b/c.pem', '/a/b/c.key', '/a/b/c.crt')
try:
    # b = BaseParser('localhost.digicert.com', '/a/b/c.pem', '/a/b/c.key', '/a/b/c.crt')
    b.load_apache_configs()
    vhost = b.get_vhost_path_by_domain()
    b.set_certificate_directives(vhost)
except Exception as e:
    print "got an exception!"
    print e.message
