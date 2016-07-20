#Set all your object files (the object files of all the .c files in your project, e.g. main.o my_sub_functions.o )
OBJ := RSA.o base64.o

#Set any dependant header files so that if they are edited they cause a complete re-compile (e.g. main.h some_subfunctions.h some_definitions_file.h ), or leave blank
DEPS :=

#Any special libraries you are using in your project (e.g. -lbcm2835 -lrt `pkg-config --libs gtk+-3.0` ), or leave blank
LIBS = -lcrypto

#Set any compiler flags you want to use (e.g. -I/usr/include/somefolder `pkg-config --cflags gtk+-3.0` ), or leave blank
CFLAGS =--std=gnu99 -Wall

#Set the compiler you are using ( gcc for C or g++ for C++ )
CC = gcc

#Set the filename extensiton of your C files (e.g. .c or .cpp )
EXTENSION = .c

#Debug options


%.o: %$(EXTENSION) $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

RSA.a: $(OBJ)
	$(CC) $^ $(CFLAGS) $(LIBS) -o $@

.PHONY: debug
debug: CFLAGS += -ggdb
debug: RSA.o
debug: RSA.a
	
#Cleanup
.PHONY: clean

clean:
	rm -f *.o *~ core *~
	rm -f *.a *~ core *~
