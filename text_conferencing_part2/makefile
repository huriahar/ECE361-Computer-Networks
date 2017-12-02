target: helper client server

helper: helper.c
	gcc -c helper.c -o helper

client: helper client.c
	gcc -pthread helper client.c -o client

server: helper server.c
	gcc helper server.c -o server

clean:
	rm -rf helper client server