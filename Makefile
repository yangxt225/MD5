CC=gcc
TARGET=testMD5

OBJECTS=md5_test.o md5.o

$(TARGET):$(OBJECTS)
	$(CC) -o $(TARGET) $(OBJECTS)
	
.c.o:
	$(CC) -o $@ -c $< 

clean:
	rm -f *.o
	rm -f $(TARGET)
