import dns

SERVER = "1.1.1.1"#your DNS server
PORT = 53#DNS server port 
dns_query = dns.message.make_query("www.baidu.com", "A")
response = dns.query.udp(dns_query, SERVER, port = PORT)

for i in response.answer:
    print (i.to_text())