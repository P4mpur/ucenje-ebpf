#include <logger.h>
#include <stdarg.h>
#include <time.h>

FILE* initialize_log(const char *filename)
{
   FILE *log_file = fopen(filename, "a");
   if (log_file == NULL)
   {
      perror("Failed to open log file");
   }
   return log_file;
}

void log_message(FILE *log_file, const char *format)
{
   if (log_file==NULL) return;

   time_t now = time(NULL);
   char time_str[20];
   strftime(time_str, sizeof(time_str),"%Y-%m-%d %H:%M:%S", localtime(&now));


   fprintf(log_file, "[%s] ", time_str);

   va_list args;
   va_start(args, format);
   vfprintf(log_file, format, args);
   va_end(args);

   fflush(log_file);
}


void close_log(FILE *log_file)
{
   if(log_file != NULL)
   {
      fclose(log_file);s
   }
}

