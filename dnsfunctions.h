#include "ndns.h"

struct gethost_reply {
  int type;             /* -1: Not found, 0: Found IP, 1: Found nameserver */
  char *details;
};
typedef struct gethost_reply ghreply;
//ghreply ngethostbyname(unsigned char *, unsigned char *, int, int);
unsigned char* ngethostbyname (unsigned char* , int);
void ChangetoDnsNameFormat (unsigned char*,unsigned char*);
unsigned char* ReadName (unsigned char*,unsigned char*,int*);
