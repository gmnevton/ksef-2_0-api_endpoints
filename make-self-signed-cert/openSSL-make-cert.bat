openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout key.pem -out cert.pem -config openssl.cnf
openssl pkcs12 -export -out cert.pfx -inkey key.pem -in cert.pem -name "Certyfikat NIP"