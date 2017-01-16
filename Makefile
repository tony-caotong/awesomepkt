# Makefile by tong @ 2017-01-13

OBJS = asmpkt.o
TARGET = asmpkt
CC = gcc
CFLAGS = -g -Wall
LDFLAGS =

$(TARGET): $(OBJS)
	gcc $(CFLAGS) $(LDFLAGS) -o $(TARGET) $(OBJS)

all: $(TARGET)

clean:
	@rm -f $(TARGET) $(OBJS)

%.o: %.c
	$(CC) $(CFLAGS) -c $<
