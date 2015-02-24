from parsers.base import BaseParser
try:
    b = BaseParser('localhost.digicert.com', '/a/b/c.pem', '/a/b/c.crt')
    b.load_apache_configs()
    vhost = b.get_vhost_path_by_domain()
    #vhost = "test"
    b.set_certificate_directives(vhost)
except Exception as e:
    print "got an exception!"
    print e.message
