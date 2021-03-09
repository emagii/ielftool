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

// Class that implements the command for calculating a checksum

#ifndef LX_ELF_CHECKSUM_CMD
#define LX_ELF_CHECKSUM_CMD

#include "LxElfCmd.h"
#include "LxElfTypes.h"
#include "LxMain.h"
#include <string>
#include <vector>

class LxElfSection;
class LxSymbolicAddress;

class ChecksumLog
{
public:
  void AddSym(const LxAddressRange & symRange);
  void AddRanges(const LxAddressRanges & ranges);

  bool RangesIncludeOldChecksum(LxAddressRanges const & mRanges) const;
  bool ChecksumIsIncludedInOldRanges(const LxAddressRange & symbolRange) const;

private:
  LxAddressRanges mSyms;
  std::vector<LxAddressRanges> mRanges;
};

class LxElfChecksumCmd :
  public LxElfCmd
{
public:
  LxElfChecksumCmd(uint8_t                   symSize,
                   LxAlgo                    algorithm,
                   LxCompl                   complement,
                   bool                      mirrorIn,
                   bool                      mirrorOut,
                   bool                      rocksoft,
                   bool                      reverse,
                   bool                      rSign,
                   uint64_t                  polynomial,
                   LxSymbolicRanges const &  ranges,
                   LxSymbolicAddress const & symbol,
                   uint64_t                  startValue,
                   StartValueType            startValueType,
                   uint8_t                   unitSize,
                   bool                      toggleEndianess);

  virtual void Execute(LxElfFile & file, bool verbose);

private:
  Elf64_Sym FindSymbol(LxElfFile const & elfFile) const;
  uint64_t CalcChecksum(LxAddressRanges const & ranges,
                        LxElfFile & file);
  void CalcAndStoreCRC(LxElfFile & inFile);

  void StoreChecksum(Elf64_Off scnOffset,
                     LxElfSection* scn,
                     uint64_t sum);

  void RemoveChecksumFromRanges(LxAddressRanges & ranges, Elf64_Addr symAddr);
  void AddDebugSymbol(std::string const & symbolName,
                      uint64_t value,
                      LxElfFile & elfFile);

private:
  bool              mVerbose;
  uint8_t           mSize;
  uint8_t           mUnitSize;
  LxAlgo            mAlgorithm;
  LxCompl           mComplement;
  bool              mMirrorIn;
  bool              mMirrorOut;
  bool              mRocksoft;
  bool              mReverse;
  bool              mRsign;
  bool              mToggleEndianess;
  uint64_t          mPolynomial;
  LxSymbolicAddress mSymbol;
  uint64_t          mSum;
  uint64_t          mStartValue;
  StartValueType    mStartValueType;

  LxSymbolicRanges mRanges;

  static ChecksumLog mLog;
};

#endif // LX_ELF_CHECKSUM_CMD
