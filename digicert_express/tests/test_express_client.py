__author__ = 'jfischer'

import unittest
import express_client


class TestExpressClient(unittest.TestCase):
    domain = 'testdomain8.com'
    order_id = '00672335'

    def test_select_from_orders(self):
        orders = express_client.select_from_orders()
        print orders
        self.assertIsNotNone(orders, msg='did not find any orders')

    def test_get_order_by_domain(self):
        orders = express_client.get_order_by_domain(self.domain)
        print orders
        self.assertIsNotNone(orders, msg='did not find any orders with domain %s' % self.domain)

    def test_something(self):
        order_info = express_client.get_order_info(self.order_id)
        print order_info
        self.assertIsNotNone(order_info, msg='could not get order info for order_id %s' % self.order_id)


if __name__ == '__main__':
    unittest.main()