#include "server.h"

#define NONBLOCKING
#define CACHE

int main(int argc, char *argv[]) {
  FILE *logFile;
  logFile = fopen(SERVERLOG, "w");
  if (logFile == NULL) {
    perror("LOGFILE OPEN ERROR!");
    exit(EXIT_FAILURE);
  }
  if (argc != 3) {
    perror("ARGV ERROR!");
    exit(EXIT_FAILURE);
  }

  runServer(argv[1], argv[2], logFile);
  fclose(logFile);

  return 0;
}