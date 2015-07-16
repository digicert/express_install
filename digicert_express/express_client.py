import os
import tempfile

from zipfile import ZipFile
from StringIO import StringIO

from express_utils import LOGGER
from express_utils import HOST
import express_utils
from cqrs import get_temp_api_key
from digicert_client import CertificateOrder


"""
Module is the interface for interacting with DigiCert client package.
All interaction with orders and digicert_client belong here.
"""


def get_order_and_domain_info(order_id, domain):
    common_name = domain
    if not order_id and not domain:
        # if we don't have an order_id or domain, then we'll query for all issued certificates
        LOGGER.info("no order_id or domain, so let's query %s for issued certificates in the account" % HOST)
        order = select_from_orders()
        order_id = order['id']
        domain = order.get('certificate', None).get('common_name', None)
        common_name = domain

    if not order_id and domain:
        LOGGER.info("querying %s for issued certificates for domain %s" % (HOST, domain))
        order = get_order_by_domain(domain)
        order_id = order.get('id', '')
        common_name = order.get('certificate', None).get('common_name', None)

    return order_id, domain, common_name


def download_cert(order_id, file_path=None, domain=None, api_key=''):
    msg_downloading = 'Downloading certificate files for: '
    msg_from_dc = 'from %s' % HOST
    if domain:
        LOGGER.info('%s domain "%s" %s (Order ID: %s)...' % (msg_downloading, domain.lower(), msg_from_dc, order_id))
    else:
        LOGGER.info('%s order ID "%s" %s...' % (msg_downloading, order_id, msg_from_dc))
    print ''

    domain = domain.lower()

    if not api_key:
        api_key = get_temp_api_key()

    if api_key:
        orderclient = CertificateOrder(HOST, api_key)
        certificates = orderclient.download(digicert_order_id=order_id)

        cert_file_path = os.path.join(file_path, 'cert.crt')
        chain_file_path = os.path.join(file_path, 'chain.pem')

        try:
            # create the download directory if it does not exist
            if file_path and not os.path.exists(file_path):
                os.mkdir(file_path.replace('*', 'star'))
                LOGGER.info('Created %s directory...' % file_path)

            if isinstance(certificates, str):
                # then we know this is a zip file containing all certs
                zip_file = ZipFile(StringIO(certificates))
                tmp_dir = tempfile.gettempdir()
                zip_file.extractall(tmp_dir)

                # get the files that were extracted
                cert_dir = os.path.join(tmp_dir, "certs")
                src_cert_file_path = os.path.join(cert_dir, '{0}.crt'.format(domain.replace(".", "_")))
                src_chain_file_path = os.path.join(cert_dir, 'DigiCertCA.crt')
                cert_file_path = os.path.join(file_path, os.path.basename(src_cert_file_path))
                chain_file_path = os.path.join(file_path, os.path.basename(src_chain_file_path))
                src_cert_file_path = src_cert_file_path.replace('*', 'star')
                cert_file_path = cert_file_path.replace('*', 'star')
                express_utils.copy_cert(src_cert_file_path, cert_file_path)
                express_utils.copy_cert(src_chain_file_path, chain_file_path)
            else:
                certificates = certificates.get('certificates')
                if not certificates:
                    raise Exception("Failed to get certificates from order ".format(order_id))

                if domain:
                    cert_file_path = os.path.join(file_path, '{0}.crt'.format(domain.replace(".", "_")))
                    chain_file_path = os.path.join(file_path, '{0}.pem'.format(domain.replace(".", "_")))

                # download the certificate
                cert = certificates.get('certificate')
                cert_file = open(cert_file_path, 'w')
                cert_file.write(cert)
                cert_file.close()

                # download the intermediate certificate
                chain = certificates.get('intermediate')
                chain_file = open(chain_file_path, 'w')
                chain_file.write(chain)
                chain_file.close()
        except IOError as ioe:
            raise Exception("Download failed: {0}".format(ioe))

        LOGGER.info('Created certificate file at path %s' % cert_file_path)
        LOGGER.info('Created certificate chain file at path %s' % chain_file_path)
        print ''
        LOGGER.info('Certificate files downloaded successfully')
        print ''

        return {'cert': cert_file_path, 'chain': chain_file_path}
    else:
        raise Exception('Username or API Key required to download certificate.')


def get_order_info(order_id, api_key=''):
    if not api_key:
        api_key = get_temp_api_key()

    if api_key:
        # call the V2 view order API
        orderclient = CertificateOrder(HOST, api_key)
        order_info = orderclient.view(digicert_order_id=order_id)
        if order_info:
            order_info['api_key'] = api_key
            return order_info
        else:
            raise Exception("ERROR: We could not find any information regarding order #{0}.".format(order_id))


def get_valid_orders(api_key=''):
    if not api_key:
        api_key = get_temp_api_key()

    if api_key:
        # call the V2 view orders API
        orders = list()
        orderclient = CertificateOrder(HOST, api_key)
        all_orders = orderclient.view_all()
        if all_orders:
            orders = list()
            for order in all_orders['orders']:
                if order['status'] == 'issued':
                    cert = order['certificate']
                    if cert:
                        orders.append(order)
            return orders
        else:
            raise Exception("ERROR: We could not find any orders for your account.")
        return


def upload_csr(order_id, csr_file, api_key=''):
    LOGGER.info("Uploading CSR file for order# {0}...".format(order_id))
    if not api_key:
        api_key = get_temp_api_key()

    if api_key:
        # call the V2 view orders API
        csr_text = None
        with open(csr_file, "r") as f:
            csr_text = f.read()

        orderclient = CertificateOrder(HOST, api_key)
        resp = orderclient.upload_csr(order_id, csr_text)
        if resp and resp['http_status']:
            # accept any 2xx status code
            import math

            result = int(math.floor(int(resp['http_status']) / 100)) * 100
            if result == 200:
                LOGGER.info("CSR uploaded successfully")
                print ""
                return True
        return False


def get_order_by_domain(domain):
    orders = get_valid_orders()
    for order in orders:
        cert = order['certificate']

        # match the domain name to the common name on the order
        common_name = cert['common_name']
        if common_name == domain:
            return order

        if domain.startswith('www.'):
            if common_name == domain.split('.', 1)[1]:
                return order
        else:
            if common_name == 'www.%s' % domain:
                return order

        # if not a direct match, look for a wildcard match
        if "*." in common_name and common_name.replace("*.", "").strip() in domain:
            return order


def select_from_orders():
    orders = get_valid_orders()
    resp = None
    if orders:
        if len(orders) > 1:
            while not resp or resp == "" or resp.isalpha():
                i = 1
                for order in orders:
                    print "{0}.\t{1}".format(i, order['certificate']['common_name'])
                    i += 1

                resp = raw_input("\nPlease select the domain you wish to secure from the list above (q to quit): ")

                if resp != 'q':
                    # validate the input catch exceptions from casting to int and validate the int value makes sense
                    try:
                        if int(resp) > len(orders) or int(resp) < 0:
                            raise Exception
                    except ValueError as e:
                        resp = None
                        print ""
                        print "ERROR: Invalid number, please try again."
                        print ""
                else:
                    raise Exception("No domain selected; aborting.")

        else:
            # there is only one order, choose it
            order_id = orders[0]['id']
            domain = orders[0]['certificate']['common_name']
            if raw_input("Continue with certificate {0} (Order ID: {1})? (Y/n)".format(domain, order_id)) != 'n':
                resp = 1
            else:
                raise Exception("No certificate selected; aborting.")

        selection = int(resp) - 1
        return orders[selection]
    else:
        raise Exception("No orders found; aborting.")


def list_duplicates(order_id, api_key=''):
    if not api_key:
        api_key = get_temp_api_key()

    if api_key:
        order_client = CertificateOrder(HOST, customer_api_key=api_key)
        return order_client.list_duplicates(order_id)


def get_duplicate(order_id, sub_id, file_path, domain, api_key=''):
    LOGGER.info("Getting duplicate")
    LOGGER.info("order id: %s sub id: %s" % (order_id, sub_id))
    if not api_key:
        api_key = get_temp_api_key()

    if api_key:
        order_client = CertificateOrder(HOST, customer_api_key=api_key)
        duplicate_data = order_client.download_duplicate(digicert_order_id=order_id, sub_id=sub_id)
        cert_file_path = os.path.join(file_path, '{0}.crt'.format(domain.replace(".", "_")))
        chain_file_path = os.path.join(file_path, '{0}.pem'.format(domain.replace(".", "_")))

        # download the certificate
        cert = duplicate_data[0]
        cert_file = open(cert_file_path, 'w')
        cert_file.write(cert)
        cert_file.close()

        # download the intermediate certificate
        chain = duplicate_data[2]
        chain_file = open(chain_file_path, 'w')
        chain_file.write(chain)
        chain_file.close()

        return {"cert": cert_file_path, "chain": chain_file_path}


def create_duplicate(order_id, cert_data, api_key=''):
    LOGGER.info("Creating duplicate")
    if not api_key:
        api_key = get_temp_api_key()

    if api_key:
        order_client = CertificateOrder(HOST, customer_api_key=api_key)
        return order_client.create_duplicate(order_id, **cert_data)
