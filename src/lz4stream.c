#include <sys/types.h>
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

static int read_stream_headers(lz4stream *lz)
{
  uint32_t signature;
  uint8_t header[3];
  uint8_t check_bits;
  uint8_t check_bits_xxh32;
  int block_size_id;

  if(read(lz->fd, &signature, sizeof(signature)) != sizeof(signature))
  {
    lz->error = "Error reading signature";
    return 0;
  };
  if(signature != LZ4STREAM_SIGNATURE)
  {
    lz->error = "Bad magic number";
    return 0;
  };
  if(read(lz->fd, header, 3) != 3)
  {
    lz->error = "Error reading header";
    return 0;
  };

#define CHECK(condition, err) \
  if((condition))             \
  {                           \
    lz->error = err;          \
    return 0;                 \
  }

  block_size_id = (header[1] >> 4) & 0x07;
  lz->block_size = 1 << (8 + (2 * block_size_id));
  lz->block_checksum_flag = header[0] & 0x10;
  lz->stream_checksum_flag = header[0] & 0x04;

  CHECK((header[0] & 0xC0) == 0, "bad version")
  CHECK((header[0] & 0x20) != 0x20, "does not block independent");
  CHECK((header[0] & 0x80) != 0, "bad stream size");
  CHECK((header[0] & 0x02) != 0, "bad reserved bits");
  CHECK((header[0] & 0x01) != 0, "dictionaries not supported");
  CHECK((header[1] & 0x8f) != 0, "bad reserved bits");
  CHECK(block_size_id < 4 || block_size_id > 7, "bad block size id");

  check_bits = header[2];
  header[1] &= 0xf0;
  check_bits_xxh32 = (XXH32(header, 2, LZ4STREAM_XXHASH_SEED) >> 8) & 0xff ;
  CHECK(check_bits_xxh32 != check_bits, "bad checksum stream header");
#undef CHECK

}

lz4stream * lz4stream_open_read(const char *filename)
{
  lz4stream *lz = calloc(1, sizeof(lz4stream));
  if(!lz)
    return NULL;

  lz->fd = open(filename, O_RDONLY);
  if(!lz->fd)
  {
    free(lz);
    return NULL;
  }

  lz->mode = O_RDONLY;
  read_stream_headers(lz);

  lz->compressed_buffer = malloc(lz->block_size);
  lz->uncompressed_buffer = malloc(2 * lz->block_size);
  return lz;
}

int lz4stream_close(lz4stream *lz)
{
  if(lz->fd)
    close(lz->fd);
  free(lz->compressed_buffer);
  free(lz->uncompressed_buffer);
}

int lz4stream_read_block(lz4stream *lz, void *tail)
{
  uint32_t len;
  uint32_t checksum;
  uint32_t calculated_checksum;

  int not_compressed;
  int tail_len = 0;
  void *compressed_data = lz->compressed_buffer;
  void *start = lz->uncompressed_buffer;

  if(lz->error) /* Do nothing in error state */
  {
    return 0;
  }

  if(lz->mode != O_RDONLY)
  {
    lz->error = "O_WRONLY stream";
    return 0;
  }

  if(read(lz->fd, &len, sizeof(len)) != sizeof(len))
  {
    lz->eof = true;
    lz->error = "Error reading length";
    return 0;
  }

  if(tail)
  {
    tail_len = lz->decoded_bytes - (tail - lz->uncompressed_buffer);
    memmove(lz->uncompressed_buffer, tail, tail_len);
    start += tail_len;
  }

  /* in case if "uncompressed data" flag, write directly in output buffer */
  not_compressed = len & 0x70000000;
  len &= 0x7FFFFFFF;

  if(not_compressed)
  {
    compressed_data = start;
  }

  int bytes = read(lz->fd, compressed_data, len);
  if(bytes != len)
  {
    lz->eof = true;
    lz->error = "Error reading compressed data";
    return 0;
  }

  if(lz->block_checksum_flag)
  {
    if(read(lz->fd, &checksum, sizeof(checksum)) != sizeof(checksum))
    {
      lz->eof = true;
      lz->error = "Error reading checksum";
      return 0;
    }

    checksum = le32toh(checksum);
    calculated_checksum = XXH32(compressed_data, len, LZ4STREAM_XXHASH_SEED);
    if(checksum != calculated_checksum)
    {
      lz->error = "bad checksum";
      return 0;
    }
  }

  if(compressed_data)
  {
    lz->decoded_bytes = LZ4_decompress_safe(
        compressed_data,
        start,
        len,
        lz->block_size
      );
   }
   else
   {
     lz->decoded_bytes = len;
   }
   lz->decoded_bytes += tail_len;
   return lz->decoded_bytes;
};

int lz4stream_get_decoded_bytes(lz4stream *lz)
{
  return lz->decoded_bytes;
}

void *lz4stream_get_buffer(lz4stream *lz)
{
  return lz->uncompressed_buffer;
}

char *lz4stream_strerror(lz4stream *lz)
{
  return lz->error;
}

int *lz4stream_eof(lz4stream *lz)
{
  return lz->eof;
}
