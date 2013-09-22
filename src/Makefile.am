lib_LTLIBRARIES = liblz4stream.la

liblz4stream_la_SOURCES = lz4stream.c xxhash.c
liblz4stream_la_LDFLAGS = -llz4 -export-symbols-regex '^lz4stream_'

include_HEADERS = lz4stream.h
