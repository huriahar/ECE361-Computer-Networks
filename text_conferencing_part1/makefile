target: helper client server

helper: helper.c
	gcc -g -c helper.c -o helper

client: helper client.c
	gcc -pthread -g helper client.c -o client

server: helper server.c
	gcc -g helper server.c -o server

clean:
	rm -rf helper client server