#include <stdio.h> // * For prints
#include <dirent.h>  // * define DIR
#include <sys/stat.h> // * struct stat (check if dir exist), mkdir
#include <alloca.h> // * alloca (allocate stack memory)
#include <string.h> // memcpy, strlen
#include <errno.h>
#include <stdbool.h>

#include "tee_logging.h"

#define CORPUS_DIR_PATH "/tmp/corpus_entries/"

// ! Dump the corpus entry (buffer) to filesystem

static void write_corpus_entry(void *buf, size_t buf_sz) 
{
	char *dir_path = CORPUS_DIR_PATH;
	FILE *f_ptr = NULL;
	struct stat f_stat = {0};
	char entry_name[10];
	char entry_full_path[PATH_MAX];
	size_t i = 0;
	bool success = 1;

	// create dir if non-existent

	if (stat(dir_path, &f_stat) == -1) {
		mkdir(dir_path, 0700);
	}

	// create a new entry in dir 

	memset(entry_full_path, 0, sizeof(entry_full_path));
	memcpy(entry_full_path, dir_path, strlen(dir_path)); // strlen counts string without null character \0

	while (1) {

		snprintf(entry_name, 10, "%zu", i); // convert int to str
		memcpy(entry_full_path + strlen(dir_path), entry_name, strlen(entry_name) + 1);

    	if (stat(entry_full_path, &f_stat) == -1)
			break;

		i++;

	}

	if ((f_ptr = fopen(entry_full_path, "wb")) == NULL) {
		OT_LOG(LOG_ERR, "fopen failed: %s\n", strerror(errno));
		success = false;
	}
		
	if (fwrite(buf, buf_sz, 1, f_ptr) != 1) { // returns nb of elements written 
		OT_LOG(LOG_ERR, "fwrite failed: %s\n", strerror(errno));
		success = false;
	} 
	
	if (success == true)
		printf("Created a new corpus entry at %s\n", entry_full_path);
	else
		printf("Failed to create a corpus entry in %s\n", entry_full_path);

	fclose(f_ptr);
}

// ! Create a corpus entry (buffer + command ID) [use this]

void create_corpus_entry(void *data, size_t data_sz, int cmd) 
{
	size_t buf_sz = sizeof(cmd) + data_sz;
	void *buf = alloca(buf_sz);
	
	memset(buf, 0, buf_sz);
	memcpy(buf, &cmd, sizeof(cmd));
	memcpy((int *)buf + 1, data, data_sz);

	write_corpus_entry(buf, buf_sz);
}

// ! Print corpuse entries

void print_corpus_entries_info() 
{
	char *dir_path = CORPUS_DIR_PATH;
	FILE *f_ptr = NULL;
	struct stat f_stat = {0};
	DIR *dir_stream;
	struct dirent *n_dir;
	char entry_full_path[PATH_MAX];
	void *buf;
	size_t buf_sz;
	int cmd;

	if (stat(dir_path, &f_stat) == -1) {
		OT_LOG(LOG_ERR, "read_corpus_entries: the input directory cannot be found\n");
		return;
	}

	// find all files in path directory

	if ((dir_stream = opendir(dir_path)) == NULL) {
		OT_LOG(LOG_ERR, "cannot open %s: %s", dir_path, strerror(errno));
		return;
	}

	memset(entry_full_path, 0, sizeof(entry_full_path));
	memcpy(entry_full_path, dir_path, strlen(dir_path)); // strlen counts string without null character \0

	if (dir_stream) {

		// skip . and .. directories
		readdir(dir_stream); 
		readdir(dir_stream); 

		while ((n_dir = readdir(dir_stream)) != NULL)
		{

			memcpy(entry_full_path + strlen(dir_path), n_dir->d_name, strlen(n_dir->d_name) + 1); // strlen counts string without null character \0

			if ((f_ptr = fopen(entry_full_path, "rb")) == NULL) {
				OT_LOG(LOG_ERR, "cannot open %s for read: %s", entry_full_path, strerror(errno));
				continue;
			}

			// find out size of file
			fseek(f_ptr, 0L, SEEK_END); // seek to the end of the file
			buf_sz = ftell(f_ptr); // ask for the position

			rewind(f_ptr); // seek back to beginning of file
			
			buf = alloca(buf_sz); // stack allocation

			fread(buf, buf_sz, 1, f_ptr);

			cmd = *(int *) (buf);
			printf("[entry_cmd=%d][entry_path=%s][entry_size=%zu]\n", cmd, entry_full_path, buf_sz);

		}
		closedir(dir_stream);	
	}
	fclose(f_ptr);
}