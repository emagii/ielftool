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

#ifndef LX_ELF_SAVE_SIMPLECODE_CMD
#define LX_ELF_SAVE_SIMPLECODE_CMD

#include "LxElfCmd.h"
#include "LxElfTypes.h"

#include <fstream>
#include <string>

#define Simple_SEG_TYPE_MASK          0x0F
#define Simple_ONE_ADDRESS_SPACE_ONLY 0x10

#define SIMPLE_CODE_VERSION	0
#define SIMPLE_CODE_MAGIC	0x7F494152

#define SEGMENT_TYPE_INVALID 0
#define SEGMENT_TYPE_CODE    1
#define SEGMENT_TYPE_DATA    2
#define SEGMENT_TYPE_XDATA   3
#define SEGMENT_TYPE_IDATA   4
#define SEGMENT_TYPE_BIT     5

#define DATA_RECORD          1
#define ENTRY_RECORD         2
#define END_RECORD           3

class LxElfSection;

class LxElfSaveSimpleCodeCmd : public LxElfCmd
{
public:
  LxElfSaveSimpleCodeCmd(const std::string &    fileName,
                         bool                   entryRecord,
                         LxElfCmdOffset const & offset);

  void virtual Execute(LxElfFile & elfFile, bool verbose);


private:
  typedef std::vector<unsigned char> Storage;
  typedef Storage::const_iterator StorageIter;

  void Dump8 (unsigned char in);
  void Dump16(unsigned int in);
  void Dump32(unsigned int in);

  void Save(LxElfFile const & file);

  void DumpFileHeader(Elf64_Addr     size,
                      Elf64_Addr     entryPoint);

  void DumpFooter();

  void DumpDataRecord(LxElfFile const & file,
                      Elf64_Addr        startAddr,
                      Elf64_Addr        accSize,
                      Storage const &   bytes);

  bool           mVerbose;
  bool           mEntryRecord;
  int            mCheckSum;
  std::string    mFileName;
  std::ofstream  mOutFile;
  LxElfCmdOffset mOffset;
};

#endif // LX_ELF_SAVE_SIMPLECODE_CMD
