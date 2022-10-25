#ifndef __CORPUS_H__
#define __CORPUS_H__

void write_corpus_entry(void *data, size_t data_sz);

void create_corpus_entry(void *data, size_t data_sz, int cmd);

void print_corpus_entries_info();

#endif