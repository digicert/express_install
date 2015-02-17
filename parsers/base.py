import augeas

class BaseParser(object):
	"""docstring for BaseParser"""
	def __init__(self, aug=None):
		if not aug:
			my_flags = augeas.Augeas.NONE | augeas.Augeas.NO_MODL_AUTOLOAD
			aug = augeas.Augeas()#flags=my_flags)
		self.aug = aug

	def load_apache_configs(self):
		self.aug.set("/augeas/load/Httpd/lens", "Httpd.lns")
		# FIXME this should be determined by the platform or webserver specific parsing settings and is norammly done automatically by augeas
		#self.aug.set("/augeas/load/Httpd/incl", "/etc/apache2/")
		self.aug.load()

	def get_vhost_path_by_domain(self, domain):
		matches = self.aug.match("/files/etc/apache2/sites-available/*")
		for host_file in matches:
			vhosts = self.aug.match(host_file+"/VirtualHost")
			if not vhosts:
				vhosts = self.aug.match(host_file+"/*/VirtualHost")
			for vhost in vhosts:
				print self.aug.get(vhost+"/arg")
				if '443' in self.aug.get(vhost+"/arg"):
					check_matches = self.aug.match(vhost+'/directive')
					if check_matches:
						for check in check_matches:
							if self.aug.get(check) == 'ServerName' and self.aug.get(check+"/arg") != None and self.aug.get(check+"/arg") == domain:
								return vhost
					else:
						check_matches = self.aug.match(vhost+'/directive')
						for check in check_matches:
							if self.aug.get(check) == 'ServerName' and self.aug.get(check+"/arg") != None and self.aug.get(check+"/arg") == domain:
								return vhost

	def set_certificate_directives(self, vhost_path, cert_path, chain_path):
		#FIXME this needs to look for and use existing existing directives in the passed vhost file
		self.aug.set(vhost_path+"/directive[last()+1]/arg", cert_path)
		self.aug.set(vhost_path+"/directive[last()]", "SSLCertificateFile")
		self.aug.set(vhost_path+"/directive[last()+1]/arg", chain_path)
		self.aug.set(vhost_path+"/directive[last()]", "SSLCertificateChainFile")
		self.aug.save()
