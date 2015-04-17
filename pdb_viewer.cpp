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
#include <errno.h>
#include <stdint.h>
#include <string>
#include <iostream>
#include <cassert>
#include <cstring>
#include <cstdio>
#include <cstddef>

#define PDB_SIGNATURE_200 "Microsoft C/C++ program database 2.00\r\n\x1AJG\0"
#define PDB_SIGNATURE_200_SIZE sizeof(PDB_SIGNATURE_200)

struct __attribute__((__packed__)) pdb_stream_t
{
    uint32_t stream_size;
    uint16_t stream_page[2];
};

struct __attribute__((__packed__)) pdb_header_t
{
    uint32_t page_size;
    uint16_t start_page;
    uint16_t file_pages;
    pdb_stream_t root_stream;
};

struct __attribute__((__packed__)) pdb_root_t
{
    uint16_t count;
    uint16_t reserved;
    pdb_stream_t streams[1];
};

typedef enum
{
    type_root_t = 0,
    type_pdb_header_t,
    type_tpi,
    type_dbi,
    type_fpo = 5,
} stream_types_t;

struct __attribute__((__packed__)) pdb_stream_header_t
{
    uint32_t version;
    uint32_t signature;
    uint32_t age;
};

struct __attribute__((__packed__)) guid_t
{
    uint32_t data1;
    uint16_t data2;
    uint16_t data3;
    uint8_t data4[8];
};

struct __attribute__((__packed__)) pdb_stream_header_ex_t
{
    pdb_stream_header_t header;
    guid_t guid;
};

typedef enum
{
    pdb_version_2 = 19941610,
    pdb_version_4 = 19950623,
    pdb_version_41 = 19950814,
    pdb_version_5 = 19960307,
    pdb_version_6 = 19970604,
    pdb_version_7p = 19990604,
    pdb_version_7 = 20000404,
} pdb_versions_t;

struct __attribute__((__packed__)) old_dbi_header_t
{
    uint16_t global_symbols_stream;
    uint16_t private_symbols_stream;
    uint16_t symbols_stream;
};

struct __attribute__((__packed__)) dbi_header_t
{
    uint32_t signature;
    uint32_t version;
    uint32_t age;
    uint16_t global_symbols_stream;
    uint16_t dll_version;
    uint16_t private_symbols_stream;
    uint16_t dll_build_number;
    uint16_t symbols_stream;
};

typedef enum
{
    dbi_version_41 = 930803,
    dbi_version_5 = 19960307,
    dbi_version_6 = 19970606,
    dbi_version_7 = 19990903,
} dbi_versions_t;

struct __attribute__((__packed__)) tpi_header_t
{
    uint32_t version;
    uint32_t header_size;
    uint32_t min_ti;
    uint32_t max_ti;
    uint32_t size;
};

typedef enum
{
    tpi_version_6 = 19961031,
} tpi_versions_t;

class pdb_file_t
{
public:
    pdb_file_t(char const * const pdb_file);
    ~pdb_file_t();

    void extract_pdb();

private:
    int validate_header();
    int open_root_stream();
    void read_stream(pdb_stream_t const * const stream, uint16_t stream_index, uint32_t pages, uint16_t const * const pages_list);

    void read_stream_root_t(pdb_stream_t const * const stream, uint16_t stream_index, void const * const stream_buffer);
    void read_stream_pdb_header_t(pdb_stream_t const * const stream, uint16_t stream_index, pdb_stream_header_ex_t const * const pdb_header);
    void read_stream_tpi(pdb_stream_t const * const stream, uint16_t stream_index, tpi_header_t const * const tpi_header);
    void read_stream_dbi(pdb_stream_t const * const stream, uint16_t stream_index, void const * const stream_buffer);
    void read_stream_fpo(pdb_stream_t const * const stream, uint16_t stream_index, void const * const stream_buffer);

    std::string _pdb_file;
    pdb_header_t _header;
    FILE * _pdb_stream;
    pdb_root_t * _root_stream;
    uint32_t _pdb_version;
    uint16_t _gs_stream;
    uint16_t _ps_stream;
    uint16_t _sym_stream;
};

static inline uint32_t min(uint32_t a, uint32_t b)
{
    if (a > b) return b;
    return a;
}

pdb_file_t::pdb_file_t(char const * const pdb_file)
{
    _pdb_file = pdb_file;
    _pdb_stream = 0;
    _root_stream = 0;
    _pdb_version = pdb_version_2;
    _gs_stream = -1;
    _ps_stream = -1;
    _sym_stream = -1;
}

pdb_file_t::~pdb_file_t()
{
    if (_pdb_stream != 0)
    {
        fclose(_pdb_stream);
        _pdb_stream = 0;
    }

    if (_root_stream != 0)
    {
        delete _root_stream;
        _root_stream = 0;
    }
}

int pdb_file_t::validate_header()
{
    struct stat buf;
    char buffer[PDB_SIGNATURE_200_SIZE + 1];

    /* Get file size */
    if (fstat(fileno(_pdb_stream), &buf) == -1)
    {
        std::cerr << "Failed to read attributes of '" << _pdb_file << "'. Error: " << errno << std::endl;
        return -1;
    }

    /* Check Signature */
    if (fread(buffer, PDB_SIGNATURE_200_SIZE, 1, _pdb_stream) != 1)
    {
        std::cerr << "Failed to read PDB signature of '" << _pdb_file << "'" << std::endl;
        return -1;
    }

    buffer[PDB_SIGNATURE_200_SIZE] = 0;
    if (strncmp(buffer, PDB_SIGNATURE_200, PDB_SIGNATURE_200_SIZE) != 0)
    {
        std::cerr << "Invalid PDB signature in '" << _pdb_file << "'" << std::endl;
        return -1;
    }

    /* Read header */
    if (fread(&_header, sizeof(pdb_header_t), 1, _pdb_stream) != 1)
    {
        std::cerr << "Failed to read PDB header of '" << _pdb_file << "'" << std::endl;
        return -1;
    }

    /* Validate header */
    if (_header.page_size != 0x400 && _header.page_size != 0x800 && _header.page_size != 0x1000)
    {
        std::cerr << "Invalid page size in PDB header of '" << _pdb_file << "': " << _header.page_size << std::endl;
        return -1;
    }
    if (_header.start_page != 0x9 && _header.start_page != 0x5 && _header.start_page != 0x2)
    {
        std::cerr << "Invalid start page in PDB header of '" << _pdb_file << "': " << _header.start_page << std::endl;
        return -1;
    }
    if ((uint16_t)(buf.st_size / _header.page_size) != _header.file_pages)
    {
        std::cerr << "Invalid number of pages in PDB header of '" << _pdb_file << "'. Got: " << _header.file_pages << ", expected: " << (uint16_t)(buf.st_size / _header.page_size) << std::endl;
        return -1;
    }
    if (_header.root_stream.stream_size == -1)
    {
        std::cerr << "Root stream marked free in '" << _pdb_file << std::endl;
        return -1;
    }

    return 0;
}

int pdb_file_t::open_root_stream()
{
    uint32_t root_size;
    uint32_t root_pages;
    uint32_t page;

    /* Prepare and validate for root stream read */
    root_size = _header.root_stream.stream_size;
    root_pages = (root_size / _header.page_size) + 1;
    if (root_size == 0 || root_pages == 0)
    {
        std::cerr << "Invalid number of root pages in '" << _pdb_file << "'" << std::endl;
        return -1;
    }

    _root_stream = static_cast<pdb_root_t *>(operator new(root_size, std::nothrow));
    if (_root_stream == 0)
    {
        std::cerr << "Memory allocation failure for " << root_size << "B\n" << std::endl;
        return -1;
    }

    /* Read the root stream */
    for (page = 0; page < root_pages; ++page)
    {
        uint16_t root_page;
        long header_position;
        long page_position;
        uint32_t to_read;

        if (fread(&root_page, sizeof(uint16_t), 1, _pdb_stream) != 1)
        {
            std::cerr << "Failed to read root page " << page << " from '" << _pdb_file << "'" << std::endl;
            return -1;
        }

        if (root_page > _header.file_pages)
        {
            std::cerr << "Root page " << page << " from '" << _pdb_file << "' beyond maximum page" << std::endl;
            return -1;
        }

        header_position = ftell(_pdb_stream);
        page_position = root_page * _header.page_size;
        if (fseek(_pdb_stream, page_position, SEEK_SET) == -1)
        {
            std::cerr << "Failed to seek root page " << page << " at " << page_position << " from '" << _pdb_file << "'" << std::endl;
            return -1;
        }

        to_read = min(_header.page_size, root_size);
        if (fread((void *)((char *)_root_stream + (page * _header.page_size)), to_read, 1, _pdb_stream) != 1)
        {
            std::cerr << "Failed to read root page " << page << " at " << page_position << " from '" << _pdb_file << "'" << std::endl;
            return -1;
        }
        root_size -= to_read;

        if (fseek(_pdb_stream, header_position, SEEK_SET) == -1)
        {
            std::cerr << "Failed to seek header position " << header_position << " from '" << _pdb_file << "'" << std::endl;
            return -1;
        }
    }

    if (root_size != 0)
    {
        std::cerr << "Inconsistent root stream read in '" << _pdb_file << "'" << std::endl;
        return -1;
    }

    /* Validate number of streams in root */
    if (offsetof(pdb_root_t, streams) + _root_stream->count * sizeof(pdb_stream_t) > _header.root_stream.stream_size)
    {
        std::cerr << "Inconsistent root stream size in '" << _pdb_file << "'\n" << std::endl;
        return -1;
    }

    return 0;
}

void pdb_file_t::read_stream_root_t(pdb_stream_t const * const stream, uint16_t stream_index, void const * const stream_buffer)
{
    if (stream->stream_size != _header.root_stream.stream_size)
    {
        std::cerr << "Mismatching root stream and copy root stream sizes in '" << _pdb_file << "'!" << std::endl;
    }

    return;
}

void pdb_file_t::read_stream_pdb_header_t(pdb_stream_t const * const stream, uint16_t stream_index, pdb_stream_header_ex_t const * const pdb_header)
{
    if (stream->stream_size < sizeof(pdb_stream_header_t))
    {
        std::cerr << "PDB header stream too small to contain its header in '" << _pdb_file << "'" << std::endl;
        return;
    }

    switch (pdb_header->header.version)
    {
        case pdb_version_2:
            std::cout << "PDB file from VisualC++ 2.0" << std::endl;
            break;

        case pdb_version_4:
        case pdb_version_41:
            std::cout << "PDB file from VisualC++ 4.0" << std::endl;
            break;

        case pdb_version_5:
            std::cout << "PDB file from VisualC++ 5.0" << std::endl;
            break;

        case pdb_version_6:
            std::cout << "PDB file from VisualC++ 6.0" << std::endl;
            break;

        case pdb_version_7p:
        case pdb_version_7:
            std::cout << "PDB file from VisualC++ 7.0" << std::endl;
            break;

        default:
            std::cout << "Unknown VisualC++ release: " << pdb_header->header.version << std::endl;
            break;
    }

    _pdb_version = pdb_header->header.version;

    if (pdb_header->header.version > pdb_version_7p)
    {
        if (stream->stream_size < sizeof(pdb_stream_header_ex_t))
        {
            std::cerr << "PDB header stream too small to contain its extended header in '" << _pdb_file << "'" << std::endl;
            return;
        }

        printf("PDB ID: %08X%04X%04X%02X%02X%02X%02X%02X%02X%02X%02X%d\n", pdb_header->guid.data1, pdb_header->guid.data2,
                                                                           pdb_header->guid.data3, pdb_header->guid.data4[0],
                                                                           pdb_header->guid.data4[1], pdb_header->guid.data4[2],
                                                                           pdb_header->guid.data4[3], pdb_header->guid.data4[4],
                                                                           pdb_header->guid.data4[5], pdb_header->guid.data4[6],
                                                                           pdb_header->guid.data4[7], pdb_header->header.age);
    }

    return;
}

void pdb_file_t::read_stream_tpi(pdb_stream_t const * const stream, uint16_t stream_index, tpi_header_t const * const tpi_header)
{
    if (stream->stream_size < sizeof(tpi_header_t))
    {
        std::cerr << "TPI stream too small to contain its header in '" << _pdb_file << "'" << std::endl;
        return;
    }

    switch (tpi_header->version)
    {
        case tpi_version_6:
            std::cout << "TPI stream from VisualC++ 6.0" << std::endl;
            break;

        default:
            std::cout << "Unknown VisualC++ release: " << tpi_header->version << std::endl;
            break;
    }

    if (tpi_header->size == 0)
    {
        if (tpi_header->min_ti != tpi_header->max_ti)
        {
            std::cout << "Corrupted header. No types information space whereas there are entries in '" << _pdb_file << "'" << std::endl;
        }
        else
        {
            std::cout << "No types information stored in '" << _pdb_file << "'" << std::endl;
        }

        return;
    }

    std::cout << "Min Type Info: " << tpi_header->min_ti << std::endl;
    std::cout << "Max Type Info: " << tpi_header->max_ti << std::endl;

    if (tpi_header->size + sizeof(tpi_header_t) > stream->stream_size)
    {
        std::cerr << "TPI stream isn't big enough in '" << _pdb_file << "' to store types information" << std::endl;
    }

    return;
}

void pdb_file_t::read_stream_dbi(pdb_stream_t const * const stream, uint16_t stream_index, void const * const stream_buffer)
{
    if (_pdb_version > pdb_version_4)
    {
        dbi_header_t const * const dbi_header = static_cast<dbi_header_t const * const>(stream_buffer);

        if (stream->stream_size < sizeof(dbi_header_t))
        {
            std::cerr << "DBI stream too small to contain its header in '" << _pdb_file << "'" << std::endl;
            return;
        }

        if (dbi_header->signature != 0xFFFFFFFF)
        {
            std::cerr << "Invalid signature for DBI stream in '" << _pdb_file << "': " << dbi_header->signature << std::endl;
            return;
        }

        switch (dbi_header->version)
        {
            case dbi_version_41:
                std::cout << "DBI stream from VisualC++ 4.0" << std::endl;
                break;

            case dbi_version_5:
                std::cout << "DBI stream from VisualC++ 5.0" << std::endl;
                break;

            case dbi_version_6:
                std::cout << "DBI stream from VisualC++ 6.0" << std::endl;
                break;

            case dbi_version_7:
                std::cout << "DBI stream from VisualC++ 7.0" << std::endl;
                break;

            default:
                std::cout << "Unknown VisualC++ release: " << dbi_header->version << std::endl;
                break;
        }

        _gs_stream = dbi_header->global_symbols_stream;
        _ps_stream = dbi_header->private_symbols_stream;
        _sym_stream = dbi_header->symbols_stream;
    }
    else
    {
        old_dbi_header_t const * const dbi_header = static_cast<old_dbi_header_t const * const>(stream_buffer);

        if (stream->stream_size < sizeof(old_dbi_header_t))
        {
            std::cerr << "DBI stream too small to contain its header in '" << _pdb_file << "'" << std::endl;
            return;
        }

        _gs_stream = dbi_header->global_symbols_stream;
        _ps_stream = dbi_header->private_symbols_stream;
        _sym_stream = dbi_header->symbols_stream;
    }

    return;
}

void pdb_file_t::read_stream_fpo(pdb_stream_t const * const stream, uint16_t stream_index, void const * const stream_buffer)
{
    std::cout << "Frame pointer omission stream found" << std::endl;
    return;
}

void pdb_file_t::read_stream(pdb_stream_t const * const stream, uint16_t stream_index, uint32_t pages, uint16_t const * const pages_list)
{
    uint32_t page;
    void * stream_buffer;
    uint32_t stream_size;

    if (pages == 0)
    {
        return;
    }

    stream_size = stream->stream_size;
    stream_buffer = operator new(stream_size, std::nothrow);
    if (stream_buffer == 0)
    {
        return;
    }

    for (page = 0; page < pages; ++page)
    {
        long page_position;
        uint32_t to_read;
        uint16_t stream_page;

        stream_page = pages_list[page];
        if (stream_page > _header.file_pages)
        {
            std::cerr << "Stream page " << page << " from '" << _pdb_file << "' beyond maximum page" << std::endl;
            goto leave;
        }

        page_position = stream_page * _header.page_size;
        if (fseek(_pdb_stream, page_position, SEEK_SET) == -1)
        {
            std::cerr << "Failed to seek stream page " << page << " at " << page_position << " from '" << _pdb_file << "'" << std::endl;
            goto leave;
        }

        to_read = min(_header.page_size, stream_size);
        if (fread((void *)((char *)stream_buffer + (page * _header.page_size)), to_read, 1, _pdb_stream) != 1)
        {
            std::cerr << "Failed to read stream page " << page << " at " << page_position << " from '" << _pdb_file << "'" << std::endl;
            goto leave;
        }

        stream_size -= to_read;
    }

    switch (stream_index)
    {
        case type_root_t:
            read_stream_root_t(stream, stream_index, stream_buffer);
            break;

        case type_pdb_header_t:
            read_stream_pdb_header_t(stream, stream_index, static_cast<pdb_stream_header_ex_t *>(stream_buffer));
            break;

        case type_tpi:
            read_stream_tpi(stream, stream_index, static_cast<tpi_header_t *>(stream_buffer));
            break;

        case type_dbi:
            read_stream_dbi(stream, stream_index, stream_buffer);
            break;

        case type_fpo:
            read_stream_fpo(stream, stream_index, stream_buffer);
            break;

        default:
            {
                if (_gs_stream < _root_stream->count && _gs_stream > type_fpo &&
                    stream_index == _gs_stream)
                {
                    std::cout << "Global symbols stream found" << std::endl;
                }
                else if (_ps_stream < _root_stream->count && _ps_stream > type_fpo &&
                         stream_index == _ps_stream)
                {
                    std::cout << "Private symbols stream found" << std::endl;
                }
                else if (_sym_stream < _root_stream->count && _sym_stream > type_fpo &&
                         stream_index == _sym_stream)
                {
                    std::cout << "Symbols stream found" << std::endl;
                }
            }
            break;
    }

leave:
    operator delete(stream_buffer);
}

void pdb_file_t::extract_pdb()
{
    uint16_t entry;
    uint32_t total_pages = 0;
    uint16_t * pages_list;

    _pdb_stream = fopen(_pdb_file.c_str(), "rb");
    if (_pdb_stream == 0)
    {
        std::cerr << "Cannot open file '" << _pdb_file << "'. Error : " << errno << std::endl;
        return;
    }

    /* Read the header and validate data */
    if (validate_header() == -1)
    {
        return;
    }


    /* Read the root stream */
    if (open_root_stream() == -1)
    {
        return;
    }

    total_pages = 0;
    pages_list = (uint16_t *)((char *)_root_stream + offsetof(pdb_root_t, streams) + _root_stream->count * sizeof(pdb_stream_t));

    for (entry = 0; entry < _root_stream->count; ++entry)
    {
        pdb_stream_t * stream;
        uint32_t pages;

        stream = &_root_stream->streams[entry];
        pages = stream->stream_size / _header.page_size + 1;
        if (stream->stream_size == 0 || stream->stream_size == -1)
        {
            pages = 0;
        }

        read_stream(stream, entry, pages, pages_list + total_pages);

        total_pages += pages;
    }

    return;
}

int main(int argc, char * argv[])
{
    int idx;

    for (idx = 1; idx < argc; ++idx)
    {
        pdb_file_t pdb_file(argv[idx]);

        pdb_file.extract_pdb();
    }

    return 0;
}
