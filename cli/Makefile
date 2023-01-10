CC = gcc

all: xwall_app

xwall_app: xwall_app.c cJSON.o
	$(CC) xwall_app.c cJSON.o -o xwall_app

cJSON.o: cJSON.c
	$(CC) -c cJSON.c

clean:
	rm *.o xwall_app

