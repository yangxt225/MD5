CC=gcc
CFLAGS=-Wall -O2
ALIB=libMD5.a
TARGET=maintest
AR=ar
ARFLAGS=-rc

OBJECTS=*.o

staticLib: $(ALIB)
main: $(TARGET)

$(TARGET): md5_test.o
	$(CC) -o $(TARGET) md5_test.o -L. -lMD5

$(ALIB): md5.o
	$(AR) $(ARFLAGS) $(ALIB) md5.o

%.o: %.c
	$(CC) -c $< $(CLAGS)

clean:
	rm -f *.o
	rm -f $(ALIB)
	rm -f $(TARGET)

