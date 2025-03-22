#ifndef LOGGER_H
#include <stdio.h>


FILE* initialize_log(const char* filename);

void log_message(FILE* log_file, const char* format);

void close_log(FILE *log_file);


#endif // !LOGGER_H
