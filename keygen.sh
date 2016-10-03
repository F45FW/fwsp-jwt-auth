openssl genrsa -out server.pem 1024
openssl rsa -in server.pem -pubout > server.pub
chmod 600 server.pem
