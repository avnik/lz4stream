#include <sys/types.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <endian.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <lz4.h>
#include "lz4stream.h"
#include "xxhash.h"

#define LZ4STREAM_SIGNATURE 0x184D2204
#define LZ4STREAM_XXHASH_SEED 0

#define LZ4S_B0_VERSION 0x40
#define LZ4S_B0_BLOCK_INDEP 0x20
#define LZ4S_B0_BLOCK_CHECKSUM 0x10
#define LZ4S_B0_STREAM_CHECKSUM 0x04

#define LZ4S_B0_VERSION_MASK 0xC0
#define LZ4S_B1_RESERVED_MASK 0x8f

static void * read_stream_headers(lz4stream * lz)
{
  uint8_t header[3] = {0, 0, 0};

  if (le32toh(*(uint32_t *)lz->mapped_file) != LZ4STREAM_SIGNATURE)
  {
    lz->error = "Bad magic number";
    return 0;
  };
  memcpy(header, lz->mapped_file + sizeof(uint32_t), sizeof(header));

#define CHECK(condition, err) \
  if ((condition))             \
  {                           \
    lz->error = err;          \
    return NULL;              \
  }

  int block_size_id = (header[1] >> 4) & 0x07;
  lz->block_size = 1 << (8 + (2 * block_size_id));
  lz->block_checksum_flag = header[0] & LZ4S_B0_BLOCK_CHECKSUM;
  lz->stream_checksum_flag = header[0] & LZ4S_B0_STREAM_CHECKSUM;

  CHECK((header[0] & LZ4S_B0_VERSION) != LZ4S_B0_VERSION, "bad version")
  CHECK((header[0] & LZ4S_B0_BLOCK_INDEP) != LZ4S_B0_BLOCK_INDEP,
    "does not block independent");
  CHECK((header[0] & 0x80) != 0, "bad stream size");
  CHECK((header[0] & 0x02) != 0, "bad reserved bits");
  CHECK((header[0] & 0x01) != 0, "dictionaries not supported");
  CHECK((header[1] & LZ4S_B1_RESERVED_MASK) != 0, "bad reserved bits");
  CHECK(block_size_id < 4 || block_size_id > 7, "bad block size id");

  uint8_t check_bits = header[2];
  header[1] &= 0xf0;
  uint8_t check_bits_xxh32 =
    (XXH32(header, 2, LZ4STREAM_XXHASH_SEED) >> 8) & 0xff ;
  CHECK(check_bits_xxh32 != check_bits, "bad checksum stream header");
#undef CHECK
  return lz->mapped_file + sizeof(uint32_t) + sizeof(header);
}

lz4stream * lz4stream_fdopen_read(int fd)
{
  lz4stream * lz = calloc(1, sizeof(lz4stream));
  struct stat sb;

  if (!lz)
  {
    close(fd);
    return NULL;
  }

  lz->fd = fd;
  lz->mode = O_RDONLY;

  if (fstat(fd, &sb))
  {
    lz->error = "fstat error";
    lz->eof = true;
    return lz;
  }

  lz->file_size = sb.st_size;
  lz->mapped_file = mmap(NULL, lz->file_size, PROT_READ, MAP_PRIVATE, fd, 0);
  if (lz->mapped_file == MAP_FAILED)
  {
    lz->error = "mmap error";
    lz->eof = true;
    return lz;
  }

  void * data_start = read_stream_headers(lz);
  if (madvise(lz->mapped_file, lz->file_size, MADV_SEQUENTIAL) != 0)
  {
    lz->error = "madvise error";
    lz->eof = true;
    return lz;
  }

  lz->compressed_buffer = data_start;
  lz->uncompressed_buffer = malloc(2 * lz->block_size);
  return lz;
}

lz4stream * lz4stream_open_read(const char * filename)
{
  int fd = open(filename, O_RDONLY);
  if (fd < 0)
  {
    return NULL;
  }
  return lz4stream_fdopen_read(fd);
}

int lz4stream_close(lz4stream * lz)
{
  uint32_t zero = 0;

  if (lz->mode == O_WRONLY && !lz->error)
  {
    lz4stream_flush(lz);

    // write end-of-stream marker
    write(lz->fd, &zero, sizeof(zero));
  }

  if (lz->mapped_file)
  {
    munmap(lz->mapped_file, lz->file_size);
  }

  if (lz->fd)
  {
    close(lz->fd);
  }

  if (lz->mode == O_WRONLY)
  {
    free(lz->compressed_buffer);
  }

  free(lz->uncompressed_buffer);
  free(lz);
}

int lz4stream_read_block(lz4stream * lz, void * tail)
{
  int tail_len = 0;
  void * compressed_data = lz->compressed_buffer;
  void * start = lz->uncompressed_buffer;

  if (lz->error) /* Do nothing in error state */
  {
    return 0;
  }

  if (lz->mode != O_RDONLY)
  {
    lz->error = "O_WRONLY stream";
    return 0;
  }

  uint32_t len = *(uint32_t *)lz->compressed_buffer;
  lz->compressed_buffer += sizeof(uint32_t);

  if (!len)
  {
    lz->eof = true;
    lz->error = "EOF";
    return 0;
  }

  if (tail)
  {
    tail_len = lz->decoded_bytes - (tail - lz->uncompressed_buffer);
    memmove(lz->uncompressed_buffer, tail, tail_len);
    start += tail_len;
  }

  /* in case if "uncompressed data" flag, write directly in output buffer */
  len = le32toh(len);
  int not_compressed = len & 0x70000000;
  len &= 0x7FFFFFFF;

  if (((lz->compressed_buffer - lz->mapped_file) + len) > lz->file_size)
  {
    lz->eof = true;
    lz->error = "Error reading compressed data (bound check)";
    return 0;
  }

  if (not_compressed)
  {
    memcpy(start, lz->compressed_buffer, len);
    lz->decoded_bytes = len;
  }
  else
  {
    compressed_data = lz->compressed_buffer;
    lz->decoded_bytes = LZ4_decompress_safe(
        compressed_data,
        start,
        len,
        lz->block_size
      );
    if (lz->decoded_bytes < 0)
    {
      lz->eof = true;
      lz->error = "malformed block or lz4 decoder internal error";
      return 0;
    }
  }

  lz->decoded_bytes += tail_len;
  lz->compressed_buffer += len;

  if (lz->block_checksum_flag)
  {
    uint32_t checksum = le32toh(*(uint32_t *)lz->compressed_buffer);
    lz->compressed_buffer += sizeof(checksum);
    uint32_t calculated_checksum = XXH32(
        compressed_data,
        len,
        LZ4STREAM_XXHASH_SEED
      );
    if (checksum != calculated_checksum)
    {
      lz->error = "bad checksum";
      return 0;
    }
  }

   return lz->decoded_bytes;
};

int lz4stream_read(lz4stream *lz, void *buffer, unsigned int len) {

  if(lz->eof && lz->tail == NULL) {
    return 0;
  }
  
  void *tail = lz->tail;
  
  int total_read = 0;
  void *start = buffer;
  
  if (tail != NULL) {
    
    int bytes_left_in_buffer = lz->decoded_bytes - (tail - lz->uncompressed_buffer);
    
    if (bytes_left_in_buffer >= len) {
      memcpy(buffer, tail, len);
      lz->tail += len;
      return len;
    } else if (bytes_left_in_buffer >= 0) {
      memcpy(buffer, tail, bytes_left_in_buffer);
      tail = NULL;
      total_read += bytes_left_in_buffer;
      start += bytes_left_in_buffer;
    }

  }

  int bytes_read;
  
  while ((bytes_read = lz4stream_read_block(lz, tail)) > 0) {
    
    tail = NULL;
    void *uncompressed_buffer = lz4stream_get_buffer(lz);
    
    if (total_read + bytes_read >= len) {
      int num_to_use = (bytes_read - (total_read + bytes_read - len));
      memcpy(start, uncompressed_buffer, num_to_use);
      total_read = len;
      tail = uncompressed_buffer + num_to_use;
      break;
    } else {
      memcpy(start, uncompressed_buffer, bytes_read);
      total_read += bytes_read;
      start += bytes_read;
    }
    
  }
  
  lz->tail = tail;
  
  return total_read;
  
}

int lz4stream_get_decoded_bytes(lz4stream * lz)
{
  return lz->decoded_bytes;
}

void * lz4stream_get_buffer(lz4stream * lz)
{
  return lz->uncompressed_buffer;
}

char * lz4stream_strerror(lz4stream * lz)
{
  return lz->error;
}

int lz4stream_eof(lz4stream * lz)
{
  return lz->eof;
}

lz4stream * lz4stream_fdopen_write(
    int fd,
    int block_size_id,
    bool block_checksum,
    bool stream_checksum
  )
{
  uint8_t header[3] = {0, 0, 0};
  uint32_t signature = htole32(LZ4STREAM_SIGNATURE);

  if (block_size_id < 4 || block_size_id > 7)
  {
    close(fd);
    return NULL;
  }

  lz4stream * lz = calloc(1, sizeof(lz4stream));
  if (!lz)
  {
    close(fd);
    return NULL;
  }

  lz->fd = fd;

  lz->mode = O_WRONLY;
  lz->block_checksum_flag = block_checksum;
  lz->stream_checksum_flag = stream_checksum;
  lz->block_size = 1 << (8 + (2 * block_size_id));

  lz->uncompressed_buffer = malloc(lz->block_size);
  lz->compressed_buffer = malloc(lz->block_size);
  lz->offset = lz->uncompressed_buffer;

  header[0] = LZ4S_B0_VERSION | LZ4S_B0_BLOCK_INDEP; // block independent
  if (lz->block_checksum_flag)
  {
    header[0] |= LZ4S_B0_BLOCK_CHECKSUM;
  }
  if (lz->stream_checksum_flag)
  {
    header[0] |= LZ4S_B0_STREAM_CHECKSUM;
  }

  header[1] = (block_size_id | 0x07) << 4;
  header[2] = (XXH32(header, 2, LZ4STREAM_XXHASH_SEED) >> 8) & 0xff ;

  if (write(lz->fd, &signature, sizeof(signature)) != sizeof(signature))
  {
    lz->error = "error writing signature";
    return lz;
  }

  if (write(lz->fd, &header, sizeof(header)) != sizeof(header))
  {
    lz->error = "error writing header";
    return lz;
  }

  return lz;
}

lz4stream * lz4stream_open_write(
    const char * filename,
    int block_size_id,
    bool block_checksum,
    bool stream_checksum
  )
{
  /* this check same as in lz4stream_fdopen_write(), but we should check
     block_size_id before open/create file */
  if (block_size_id < 4 || block_size_id > 7)
  {
    return NULL;
  }

  int fd = open(filename, O_WRONLY | O_CREAT, 0644);
  if (fd < 0)
  {
    return NULL;
  };

  return lz4stream_fdopen_write(
      fd,
      block_size_id,
      block_checksum,
      stream_checksum
    );
}

int lz4stream_write_block(lz4stream * lz, void * block, int size)
{
  uint32_t bytes = LZ4_compress_limitedOutput(
      block,
      lz->compressed_buffer,
      size,
      lz->block_size
    );

  if (bytes < 0)
  {
    lz->error = "internal LZ4 error";
    return 0;
  }

  uint32_t bytes_le32 = htole32(bytes);
  if (write(lz->fd, &bytes_le32, sizeof(bytes_le32)) != sizeof(bytes_le32))
  {
    lz->error = "error writing block length";
    return 0;
  }

  if (write(lz->fd, lz->compressed_buffer, bytes) != bytes)
  {
    lz->error = "error writing data block";
    return 0;
  }

  if (lz->block_checksum_flag)
  {
    uint32_t checksum = htole32(
        XXH32(lz->compressed_buffer, bytes, LZ4STREAM_XXHASH_SEED)
      );
    if (write(lz->fd, &checksum, sizeof(checksum)) != sizeof(checksum))
    {
      lz->error = "error writing checksum";
      return 0;
    }
  }

  return size;
}

int lz4stream_flush(lz4stream * lz)
{
  int bytes = lz4stream_write_block(
      lz,
      lz->uncompressed_buffer,
      lz->offset - lz->uncompressed_buffer
    );
  if (bytes)
  {
    lz->offset = lz->uncompressed_buffer;
  }
  return bytes;
}

int lz4stream_write(lz4stream * lz, void * data, int size)
{
  if (size > lz->block_size)
  {
    lz->error = "data large then buffer";
    return 0;
  }

  if ((lz->offset - lz->uncompressed_buffer + size) > lz->block_size)
  {
    int size1 = lz->block_size - (lz->offset - lz->uncompressed_buffer);
    memcpy(lz->offset, data, size1);
    lz->offset += size1;

    if (lz4stream_flush(lz) == 0) // escalate error
    {
      return 0;
    }

    memcpy(lz->offset, data + size1, size - size1);
    lz->offset += size - size1;
  }
  else
  {
    memcpy(lz->offset, data, size);
    lz->offset += size;
  }
  return size;
}
