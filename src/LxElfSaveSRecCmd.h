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

/* $Rev: 60303 $ */

// Class that implements the command for saving S-records

#ifndef LX_ELF_SAVE_SREC_CMD
#define LX_ELF_SAVE_SREC_CMD

#include "LxElfSaveCmdBase.h"

class LxElfSaveSRecCmd : public LxElfSaveCmdBase
{
public:
  LxElfSaveSRecCmd(std::string const &    fileName,
                   SRecVariant            variant,
                   unsigned char          len,
                   LxElfCmdOffset const & offset);

  virtual void DumpHeader(LxElfFile const & elfFile, std::ostream & o);
  virtual bool DumpData  (LxElfFile const & file,
                          Elf64_Addr addr,
                          Elf64_Addr next,
                          LxElfDataBuffer const & data,
                          bool verbose,
                          bool continueRecord,
                          std::ostream & o);
  virtual void DumpFooter(LxElfFile const & elfFile, std::ostream & o);

private:
  const SRecVariant & GetVariantToUse(Elf64_Addr addr) const;
  Elf64_Addr          GetNextVariantAddr(Elf64_Addr addr) const;

  Elf64_Addr          DumpRecord(LxElfFile const &       file,
                                 Elf64_Addr              currAddr,
                                 Elf64_Addr              nextAddr,
                                 Elf64_Addr              dataStartAddr,
                                 LxElfDataBuffer const & bytes,
                                 bool &                  continueRecord,
                                 std::ostream &          os);

  Elf64_Addr          ContinueRecord(LxElfFile const &       file, 
                                     Elf64_Addr              currAddr,
                                     Elf64_Addr              dataStartAddr,
                                     LxElfDataBuffer const & bytes,
                                     bool &                  continueRecord,
                                     std::ostream &          os);

  void                FinishRecord(Elf64_Addr                currAddr);

  SRecVariant    mVariant;
  unsigned char  mMaxRecordLength;
  LxElfCmdOffset mOffset;
};

#endif // LX_ELF_SAVE_SREC_CMD
