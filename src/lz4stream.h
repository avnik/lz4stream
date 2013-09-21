#ifndef _LZ4_STREAM_H
#define _LZ4_STREAM_H 1

typedef struct lz4stream_t lz4stream;

lz4stream * lz4stream_open_read(const char *filename);

/* NOTE: lz4stream_fdopen_read() close fd if error occured,
   also fd will be closed by lz4stream_close() */
lz4stream * lz4stream_fdopen_read(int fd);
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

/* NOTE: lz4stream_fdopen_write() close fd if error occured,
   also fd will be closed by lz4stream_close() */
lz4stream *lz4stream_fdopen_write(
    int fd,
    int block_size,
    bool block_checksum,
    bool stream_checksum
  );


int lz4stream_write_block(lz4stream *lz, void *block, int size);
int lz4stream_flush(lz4stream *lz);
int lz4stream_write(lz4stream *lz, void *data, int size);

#endif
