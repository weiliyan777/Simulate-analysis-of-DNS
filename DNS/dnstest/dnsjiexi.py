from dns import resolver
 
 
class QueryDNSResolver:
    """DNS解析，A类、MX、NS、CNAME"""
    def __init__(self):
        pass
 
    def A_query(self, domain):
        try:
            A_items = resolver.query(domain, 'A')
            for i in A_items.response.answer:
                for j in i.items:
                    if j.rdtype == 1:
                        print(j.address)
        except resolver.NoAnswer as e:
            print(e)
 
    def MX_query(self, domain):
        try:
            MX_items = resolver.query(domain, 'MX')
            for i in MX_items:
                print('MX preference =', i.preference, 'main exchanger =', i.exchange)
        except resolver.NoAnswer as e:
            print(e)
 
    def NS_query(self, domain):
        try:
            self.__Base_query(domain, 'NS')
        except resolver.NoAnswer as e:
            print(e)
        '''
        NS_items = resolver.query(domain, 'NS')
        for i in NS_items.response.answer:
            for j in i.items:
                print(j.to_next())
                '''
 
    def CNAME_query(self, domain):
        try:
            self.__Base_query(domain, 'CNAME')
        except resolver.NoAnswer as e:
            print(e)
        '''
        CNAME_items = resolver.query(domain, 'CNAME')
        for i in CNAME_items.response.answer:
            for j in i.items:
                print(j.to_next())
                '''
 
    def __Base_query(self, domain, queryMode):
        try:
            items = resolver.query(domain, queryMode)
            for i in items.response.answer:
                for j in i.items:
                    print(j.to_text())
        except resolver.NoAnswer as e:
            print(e)
 
    def ALL_query(self, domain):
 
        self.__print_info('A')
        self.A_query(domain)
 
        self.__print_info('MX')
        self.MX_query(domain)
 
        self.__print_info('NS')
        self.NS_query(domain)
 
        self.__print_info('CNAME')
        self.CNAME_query(domain)
 
    def __print_info(self, queryMode):
        print('====%s====\n' % str(queryMode))
 
 
def main():
    query_ob = QueryDNSResolver()
    domain = input('Enter an domain:')
    query_ob.ALL_query(domain)
 
if __name__ == '__main__':
    main()