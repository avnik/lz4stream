#ifndef _LZ4_STREAM_H
#define _LZ4_STREAM_H 1

typedef struct lz4stream_t
{
  int   fd; // compressed file
  void *compressed_buffer; // buffer for compressed data
  int   compressed_buffer_size;
  void *uncompressed_buffer;
  int   decoded_bytes;
  int   mode;
  char *error;

  bool  block_checksum_flag;
  bool  stream_checksum_flag;
  int   block_size;
  int   eof;
  void *offset;
} lz4stream;

lz4stream * lz4stream_open_read(const char *filename);
int lz4stream_close(lz4stream *lz);
int lz4stream_read_block(lz4stream *lz, void *tail);
char *lz4stream_strerror(lz4stream *lz);

/* access decoded data */
void *lz4stream_get_buffer(lz4stream *lz);
int lz4stream_get_decoded_bytes(lz4stream *lz);
int lz4stream_eof(lz4stream *lz);

lz4stream *lz4stream_open_write(
    const char *filename,
    int block_size,
    bool block_checksum,
    bool stream_checksum
  );

int lz4stream_write_block(lz4stream *lz, void *block, int size);
int lz4stream_flush(lz4stream *lz);
int lz4stream_write(lz4stream *lz, void *data, int size);

#endif
