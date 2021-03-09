///////////////////////////////// -*- C++ -*- /////////////////////////////////
/*
 * Copyright 2007-2017 IAR Systems AB.
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/* $Rev: 57699 $ */

// Class that implements the command for saving a SimpleCode file

#include "LxElfSaveSimpleCode.h"
#include "LxElfException.h"
#include "LxElfFile.h"
#include "unicode_output.h"

#include <algorithm>

#include "LxOutput.h"           // last include

using namespace std;

using unicode_output::ucout;

void
LxElfSaveSimpleCodeCmd::Dump8(unsigned char in)
{
  /* Everything goes through here - so here we build up the checksum as well */
  mCheckSum += in;
  mOutFile << in;
}

void
LxElfSaveSimpleCodeCmd::Dump16(unsigned int in)
{
  Dump8 ((in >> 8) & 0xFF);
  Dump8 (in & 0xFF);
}

void
LxElfSaveSimpleCodeCmd::Dump32(unsigned int in)
{
  Dump16 ((in >> 16) & 0xFFFF);
  Dump16 (in & 0xFFFF);
}

void
LxElfSaveSimpleCodeCmd::DumpFileHeader(Elf64_Addr     size,
                                       Elf64_Addr     entryPoint)
{
  Dump32 (SIMPLE_CODE_MAGIC);    // Magic number
  Dump32 (0);                    // Program flags - zeroes for now
  Dump32 (LxCheck32(size));      // Number of code bytes
  Dump16 (SIMPLE_CODE_VERSION);  // Version
  if (mVerbose)
  {
    ucout << "  Dumping " << size << " code bytes\n";
  }

  if (mEntryRecord)
  {
    Dump8 (ENTRY_RECORD);
    Dump32(LxCheck32(entryPoint));
    Dump8 (SEGMENT_TYPE_CODE);
    if (mVerbose)
    {
      ucout << "  Entry address: 0x" << (hex) << (uppercase)
            << entryPoint << (dec) << "\n";
    }
  }
}

void
LxElfSaveSimpleCodeCmd::DumpDataRecord(LxElfFile const & file,
                                       Elf64_Addr        startAddr,
                                       Elf64_Addr        accSize,
                                       Storage const &   bytes)
{
  if (accSize)
  {
    Elf64_Addr actualAddr = mOffset.Modify(startAddr, file.Is64Bit());
    Dump8 (DATA_RECORD);       // data record
    Dump8 (SEGMENT_TYPE_CODE); // type is code
    Dump16(0);                 // flags
    Dump32(LxCheck32(actualAddr)); // first address
    Dump32(LxCheck32(accSize));// number of bytes
    // the bytes themselves
    for (StorageIter p = bytes.begin(), q = bytes.end() ; p != q ; ++p)
      Dump8(*p);
    if (mVerbose)
    {
      ucout << "  Data record - address: 0x" << (hex) << (uppercase)
          << actualAddr << (dec) << "\n"
          << "                   size: 0x" << (hex) << (uppercase)
          << accSize << (dec) << "\n";
    }
  }
}

namespace
{
  typedef LxElfConstSegments::const_iterator SIter;
  typedef LxElfDataBuffer::const_iterator    DIter;
}

static
void
GetAddresses(SIter i, SIter n, Elf64_Addr & current, Elf64_Addr & next)
{
  // current physical address
  current = (*i)->mHdr.p_paddr;
  // next segment
  SIter j = i+1;

  if (j == n || (*j)->mHdr.p_memsz == 0)
	// no next element, or an empty one
    next = current - 1;
  else
	// non empty next element, use it
    next = (*j)->mHdr.p_paddr;
}

void
LxElfSaveSimpleCodeCmd::Save(LxElfFile const & file)
{
  LxElfConstSegments segs = file.GetLoadSegments();

  Elf64_Addr size = 0;

  // get the sum of the sizes of all segments
  for (SIter i = segs.begin(), n = segs.end(); i != n; ++i)
    size += (*i)->mHdr.p_filesz;

  // generate the file header and entry record
  DumpFileHeader(size, file.GetEntryAddr());

  typedef std::vector<unsigned char> Storage;
  typedef Storage::const_iterator StorageIter;
  Storage bytes;

  Elf64_Addr accSize = 0, startAddr = 0, nextAddr  = 0-1;

  // iterate over all segments,
  // transfer bytes to storage and
  // dump when a gap is encountered
  for (SIter i = segs.begin(), n = segs.end() ; i != n ; ++i)
  {
    Elf64_Addr currAddr = (*i)->mHdr.p_paddr, size = (*i)->mHdr.p_filesz;

    // there is a gap, output a new record
    if (   (nextAddr < currAddr)
        && (nextAddr + 1) != currAddr)
    {
      DumpDataRecord(file, startAddr, accSize, bytes);

      bytes.clear();
      accSize   = 0;
      startAddr = currAddr;
    }
    else if (nextAddr > currAddr)
    {
	  // first segment only
      startAddr = currAddr;
    }


    // a segment can be empty
    if (size)
    {
      accSize += size;
      DIter p = (*i)->mData.begin(), q = (*i)->mData.end();

      // get the bytes into the storage
      for ( ; p != q ; ++p)
        bytes.push_back(*p);
    }

    nextAddr = currAddr + size;
  }
  if (accSize)
  {
    DumpDataRecord(file, startAddr, accSize, bytes);
  }
  DumpFooter();
}

void
LxElfSaveSimpleCodeCmd::DumpFooter()
{
  Dump8(END_RECORD);

  // the checksum is done now
  int theChecksum = 0 - mCheckSum;
  Dump32(theChecksum);

  if (mVerbose)
  {
    ucout << "  Checksum: 0x" << (hex) << (uppercase)
          << theChecksum << (dec) << "\n";
  }
}

/*================*/
/* public methods */
/*================*/

LxElfSaveSimpleCodeCmd::
LxElfSaveSimpleCodeCmd(const string &         fileName,
                       bool                   entryRecord,
                       LxElfCmdOffset const & offset)
: mFileName(fileName),
  mEntryRecord(entryRecord),
  mOffset(offset)
{
  /* mOutFile gets a default construction here, it is opened in Execute () */
  mVerbose  = false;
  mCheckSum = 0;
}


void LxElfSaveSimpleCodeCmd::
Execute(LxElfFile & elfFile, bool verbose)
{
  if (verbose)
  {
    ucout << "Saving SimpleCode file to " << LxFixFilename(mFileName).c_str()
          << endl;
    mVerbose = true;
  }

  mOutFile.open(LxFixFilename(mFileName).c_str(), ios::binary);
  Save(elfFile);
}
