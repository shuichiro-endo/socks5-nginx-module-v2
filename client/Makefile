CC		= gcc
CFLAGS		=
LDFLAGS		= -lssl -lcrypto -pthread -lgssapi_krb5
LIBS		=
SRCS		= client.c
OBJS		= $(SRCS:.c=.o)
TARGET		= client

all:		clean $(TARGET)

$(TARGET):	$(OBJS)
		$(CC) $^ $(LDFLAGS) $(LIBS) -o $@

clean:;		rm -f *.o *~ $(TARGET)

