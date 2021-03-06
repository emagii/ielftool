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

/* $Rev: 58192 $ */

// Class that implements the command for saving as binary

#ifndef LX_ELF_SAVE_BIN_CMD
#define LX_ELF_SAVE_BIN_CMD

#include "LxElfCmd.h"
#include "LxElfTypes.h"
#include "LxMain.h"

#include <string>
#include <fstream>

class LxElfSection;

class LxElfSaveBinCmd : public LxElfCmd
{
public:
  LxElfSaveBinCmd(const std::string & fileName, bool multipleFiles,
                  LxSymbolicRanges const & ranges);

  virtual void Execute(LxElfFile & file, bool verbose);

private:
  void Save(LxElfFile const & file,
            bool verbose) const;

  void PadFile(std::ofstream & outFile, Elf64_Word len) const;

protected:
  std::string      mFileName;
  bool             mMultipleFiles;
  LxSymbolicRanges mRanges;
};

#endif // LX_ELF_SAVE_BIN_CMD
