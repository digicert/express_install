__author__ = 'jfischer'

import unittest
import express_install


class TestExpressClient(unittest.TestCase):
    def test_verify_requirements(self):
        express_install.verify_requirements()

    def test_do_everything(self):
        express_install.do_everything_with_args(order_id='00683449', domain='testdomain.com', create_csr=True)
        print 'finished'

    def test_prompt_for_domains(self):
        virtual_hosts = ['test.com', 'test2.com', 'test3.com']
        choices = zip(range(1, len(virtual_hosts)+1), virtual_hosts)

        # print 'select virtual hosts: \n' + "\n".join(virtual_hosts)
        count = 1
        for virtual_host in virtual_hosts:
            print "%s. %s" % (count, virtual_host)
            count += 1
        # selection = raw_input("choose a number")
        import time
        time.sleep(4)
        print "selection is: %s" % '1,2'
        selection = '1,2'
        selection = selection.split(',')
        print selection

        selected_hosts = []
        for x in selection:
            for choice in choices:
                if int(x) == choice[0]:
                    selected_hosts.append(choice[1])

        print 'final:'
        print selected_hosts

    def test_print_choices(self):
        l = list()
        l.append((1, 'nocsr.com'))
        l.append((2, 'test.nocsr.com'))
        strings = list()
        for x in l:
            s = [str(a) for a in x]
            strings.append(". ".join(s))
        doc = "\n".join(strings)
        print doc


if __name__ == '__main__':
    unittest.main()