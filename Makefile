CC=gcc
CFLAGS=-Wall -O2
ATRIPLEDES=libMD5.a
TARGET=maintest
AR=ar
ARFLAGS=-rc

OBJECTS=*.o

staticLib: $(ATRIPLEDES)
main: $(TARGET)

$(TARGET): md5_test.o
	$(CC) -o $(TARGET) md5_test.o -L. -lMD5

$(ATRIPLEDES): md5.o
	$(AR) $(ARFLAGS) $(ATRIPLEDES) md5.o

%.o: %.c
	$(CC) -c $< $(CLAGS)

clean:
	rm -f *.o
	rm -f $(ATRIPLEDES)
	rm -f $(TARGET)

