
SERVER_FILE=./simple_serv/simple_server.c
CLIENT_FILE=./simple_cli/simple_client.c

SERVER_OUT_FILE=simple_server
CLIENT_OUT_FILE=simple_client


compile: server client

server: $(SERVER_FILE)
	gcc -o $(SERVER_OUT_FILE) $(SERVER_FILE)

client: $(CLIENT_FILE)
	gcc -o $(CLIENT_OUT_FILE) $(CLIENT_FILE)

clean:
	rm $(SERVER_OUT_FILE) $(CLIENT_OUT_FILE)
