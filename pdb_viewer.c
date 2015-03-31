/*
* pdb_viewer - A tool for dumping contents of PDB files
* Copyright (C) 2015 Pierre Schweitzer <pierre@reactos.org>
*
* This program is free software: you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation, either version 3 of the License, or
* (at your option) any later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
* GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License
* along with this program. If not, see <http://www.gnu.org/licenses/>.
*
* This work is based on:
* Schreiber, Sven B. Undocumented Windows 2000 secrets: a programmer's cookbook. Reading: Addison-Wesley, 2001.
* ISBN: 0201721872
*/

#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <assert.h>
#include <stdlib.h>
#include <stddef.h>

#define PDB_SIGNATURE_200 "Microsoft C/C++ program database 2.00\r\n\x1AJG\0"
#define PDB_SIGNATURE_200_SIZE sizeof(PDB_SIGNATURE_200)

typedef struct __attribute__((__packed__)) _pdb_stream_t
{
    uint32_t stream_size;
    uint16_t stream_page[2];
} pdb_stream_t;

typedef struct __attribute__((__packed__)) _pdb_header_t
{
    uint32_t page_size;
    uint16_t start_page;
    uint16_t file_pages;
    pdb_stream_t root_stream;
} pdb_header_t;

typedef struct __attribute__((__packed__)) _pdb_root_t
{
    uint16_t count;
    uint16_t reserved;
    pdb_stream_t streams[1];
} pdb_root_t;

static inline uint32_t min(uint32_t a, uint32_t b)
{
    if (a > b) return b;
    return a;
}

static int validate_header(char const * const pdb_file, FILE * const pdb_stream, pdb_header_t * const header)
{
    struct stat buf;
    char buffer[PDB_SIGNATURE_200_SIZE + 1];

    /* Get file size */
    if (fstat(fileno(pdb_stream), &buf) == -1)
    {
        fprintf(stderr, "Failed to read attributes of '%s'. Error: %d\n", pdb_file, errno);
        return -1;
    }

    /* Check Signature */
    if (fread(buffer, PDB_SIGNATURE_200_SIZE, 1, pdb_stream) != 1)
    {
        fprintf(stderr, "Failed to read PDB signature of '%s'\n", pdb_file);
        return -1;
    }

    buffer[PDB_SIGNATURE_200_SIZE] = 0;
    if (strncmp(buffer, PDB_SIGNATURE_200, PDB_SIGNATURE_200_SIZE) != 0)
    {
        fprintf(stderr, "Invalid PDB signature in '%s'\n", pdb_file);
        return -1;
    }

    /* Read header */
    if (fread(header, sizeof(pdb_header_t), 1, pdb_stream) != 1)
    {
        fprintf(stderr, "Failed to read PDB header of '%s'\n", pdb_file);
        return -1;
    }

    /* Validate header */
    if (header->page_size != 0x400 && header->page_size != 0x800 && header->page_size != 0x1000)
    {
        fprintf(stderr, "Invalid page size in PDB header of '%s': %x\n", pdb_file, header->page_size);
        return -1;
    }
    if (header->start_page != 0x9 && header->start_page != 0x5 && header->start_page != 0x2)
    {
        fprintf(stderr, "Invalid start page in PDB header of '%s': %x\n", pdb_file, header->start_page);
        return -1;
    }
    if ((uint16_t)(buf.st_size / header->page_size) != header->file_pages)
    {
        fprintf(stderr, "Invalid number of pages in PDB header of '%s'. Got: %u, expected: %u\n", pdb_file, header->file_pages, (uint16_t)(buf.st_size / header->page_size));
        return -1;
    }
    if (header->root_stream.stream_size == -1)
    {
        fprintf(stderr, "Root stream marked free in '%s'\n", pdb_file);
        return -1;
    }

    return 0;
}

static pdb_root_t * open_root_stream(char const * const pdb_file, FILE * const pdb_stream, pdb_header_t const * const header)
{
    int error = 0;
    uint32_t root_size;
    uint32_t root_pages;
    pdb_root_t * root_stream = NULL;
    uint32_t page;

    /* Prepare and validate for root stream read */
    root_size = header->root_stream.stream_size;
    root_pages = (root_size / header->page_size) + 1;
    if (root_size == 0 || root_pages == 0)
    {
        fprintf(stderr, "Invalid number of root pages in '%s'\n", pdb_file);
        return NULL;
    }

    root_stream = malloc(root_size);
    if (root_stream == NULL)
    {
        fprintf(stderr, "Memory allocation failure for %xB\n", header->root_stream.stream_size);
        return NULL;
    }

    /* Read the root stream */
    for (page = 0; page < root_pages; ++page)
    {
        uint16_t root_page;
        long header_position;
        long page_position;
        uint32_t to_read;

        if (fread(&root_page, sizeof(uint16_t), 1, pdb_stream) != 1)
        {
            fprintf(stderr, "Failed to read root page %u from '%s'\n", page, pdb_file);
            error = 1;
            goto leave;
        }

        header_position = ftell(pdb_stream);
        page_position = root_page * header->page_size;
        if (fseek(pdb_stream, page_position, SEEK_SET) == -1)
        {
            fprintf(stderr, "Failed to seek root page %u at %lx from '%s'\n", page, page_position, pdb_file);
            error = 1;
            goto leave;
        }

        to_read = min(header->page_size, root_size);
        if (fread((void *)((char *)root_stream + (page * header->page_size)), to_read, 1, pdb_stream) != 1)
        {
            fprintf(stderr, "Failed to read root page %u at %lx from '%s'\n", page, page_position, pdb_file);
            error = 1;
            goto leave;
        }
        root_size -= to_read;

        if (fseek(pdb_stream, header_position, SEEK_SET) == -1)
        {
            fprintf(stderr, "Failed to seek header position %lx from '%s'\n", header_position, pdb_file);
            error = 1;
            goto leave;
        }
    }

    if (root_size != 0)
    {
        fprintf(stderr, "Inconsistent root stream read in '%s'\n", pdb_file);
        error = 1;
        goto leave;
    }

    /* Validate number of streams in root */
    if (offsetof(pdb_root_t, streams) + root_stream->count * sizeof(pdb_stream_t) > header->root_stream.stream_size)
    {
        fprintf(stderr, "Inconsistent root stream size in '%s'\n", pdb_file);
        error = 1;
        goto leave;
    }

leave:
    if (error)
    {
        free(root_stream);
        root_stream = NULL;
    }

    return root_stream;
}

static void read_stream(char const * const pdb_file, FILE * const pdb_stream, pdb_stream_t const * const stream, uint32_t pages, uint16_t const * const pages_list)
{
    uint32_t page;

    printf("Stream size: %x\n", stream->stream_size);
    printf("Stream pages: %x\n", pages);

    if (pages == 0)
    {
        return;
    }

    printf("Stream pages list: ");
    for (page = 0; page < pages; ++page)
    {
        printf("%x ", pages_list[page]);
    }
    printf("\n");
}

static void extract_pdb(char const * const pdb_file)
{
    FILE * pdb_stream;
    pdb_header_t header;
    pdb_root_t * root_stream = NULL;
    uint32_t entry;
    uint32_t total_pages = 0;
    uint16_t * pages_list;
    uint32_t page;

    pdb_stream = fopen(pdb_file, "rb");
    if (pdb_stream == NULL)
    {
        fprintf(stderr, "Cannot open file '%s'. Error: %d\n", pdb_file, errno);
        return;
    }

    /* Read the header and validate data */
    if (validate_header(pdb_file, pdb_stream, &header) == -1)
    {
        goto leave;
    }


    /* Read the root stream */
    root_stream = open_root_stream(pdb_file, pdb_stream, &header);
    if (root_stream == NULL)
    {
        goto leave;
    }

    total_pages = 0;
    pages_list = (uint16_t *)((char *)root_stream + offsetof(pdb_root_t, streams) + root_stream->count * sizeof(pdb_stream_t));

    for (entry = 0; entry < root_stream->count; ++entry)
    {
        pdb_stream_t * stream;
        uint32_t pages;

        stream = &root_stream->streams[entry];
        pages = stream->stream_size / header.page_size + 1;
        if (stream->stream_size == 0)
        {
            pages = 0;
        }

        read_stream(pdb_file, pdb_stream, stream, pages, (uint16_t *)((char *)pages_list + total_pages));

        total_pages += pages;
    }

leave:
    free(root_stream);
    fclose(pdb_stream);
    return;
}

int main(int argc, char * argv[])
{
    int idx;

    for (idx = 1; idx < argc; ++idx)
    {
        extract_pdb(argv[idx]);
    }

    return 0;
}
