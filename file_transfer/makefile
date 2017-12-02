edit: helper deliver server

helper : helper.c
	gcc helper.c -c -o helper

deliver: helper deliver.c
	gcc helper deliver.c -o deliver

server: helper server.c
	gcc helper server.c -o server

clean:
	rm -rf helper deliver server