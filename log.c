#include "log.h"

void logRequestEvent(FILE *logFile, char *domain_name) {
  char cur_time[TIME_SIZE];
  getTime(cur_time);
  const char info[12] = " requested ";
  fwrite(cur_time, strlen(cur_time), 1, logFile);
  fwrite(info, strlen(info), 1, logFile);
  fwrite(domain_name, strlen(domain_name), 1, logFile);
  fwrite("\n", 1, 1, logFile);
  fflush(logFile);
}

void logRequestNotFoundEvent(FILE *logFile) {
  char cur_time[TIME_SIZE];
  getTime(cur_time);
  const char info[23] = " unimplemented request";
  fwrite(cur_time, strlen(cur_time), 1, logFile);
  fwrite(info, strlen(info), 1, logFile);
  fwrite("\n", 1, 1, logFile);
  fflush(logFile);
}

void logExpiresEvent(FILE *logFile, char *domain_name, char *expire_time) {
  char cur_time[TIME_SIZE];
  getTime(cur_time);
  const char info[13] = " expires at ";
  fwrite(cur_time, strlen(cur_time), 1, logFile);
  fwrite(" ", 1, 1, logFile);
  fwrite(domain_name, strlen(domain_name), 1, logFile);
  fwrite(info, strlen(info), 1, logFile);
  fwrite(expire_time, strlen(expire_time), 1, logFile);
  fwrite("\n", 1, 1, logFile);
  fflush(logFile);
}

void logReplacingEvent(FILE *logFile, char *domain_name,
                       char *cache_domain_name) {
  char cur_time[TIME_SIZE];
  getTime(cur_time);
  const char info_1[12] = " replacing ";
  const char info_2[5] = " by ";
  fwrite(cur_time, strlen(cur_time), 1, logFile);
  fwrite(info_1, strlen(info_1), 1, logFile);
  fwrite(cache_domain_name, strlen(cache_domain_name), 1, logFile);
  fwrite(info_2, strlen(info_2), 1, logFile);
  fwrite(domain_name, strlen(domain_name), 1, logFile);
  fwrite("\n", 1, 1, logFile);
  fflush(logFile);
}

void logLookUpEvent(FILE *logFile, char *domain_name, char *IP) {
  char cur_time[TIME_SIZE];
  getTime(cur_time);
  const char info[8] = " is at ";
  fwrite(cur_time, strlen(cur_time), 1, logFile);
  fwrite(" ", 1, 1, logFile);
  fwrite(domain_name, strlen(domain_name), 1, logFile);
  fwrite(info, strlen(info), 1, logFile);
  fwrite(IP, strlen(IP), 1, logFile);
  fwrite("\n", 1, 1, logFile);
  fflush(logFile);
}

void getTime(char *buffer) {
  time_t cur_time;
  struct tm *time_info;

  time(&cur_time);
  time_info = localtime(&cur_time);
  strftime(buffer, TIME_SIZE, TIME_FORMAT, time_info);
}