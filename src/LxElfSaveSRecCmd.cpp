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

#include "LxElfSaveSRecCmd.h"

#include "LxElfFile.h"
#include <algorithm>
#include <sstream>

using namespace std;

namespace
{
  class RecordChecksum
  {
  public:
    RecordChecksum() : mChecksum(0) {}

    void Clear()
    {
      mChecksum = 0;
    }

    void Add(unsigned char data)
    {
      mChecksum += data;
    }

    void Finalize()
    {
      mChecksum = 255 - (mChecksum & 0xff);
    }

    unsigned int Get() const
    {
      return mChecksum;
    }

  private:
    unsigned int mChecksum;
  };

  class RecordDumper
  {
  public:
    RecordDumper(std::ostream & os) : mOs(os) {}

    RecordDumper(vector<unsigned char>::size_type size, std::ostream & os)
      : mOs(os)
    {
      mData.reserve(size);
    }

#if 0
    void Clear()
    {
      mData.clear();
      mChecksum.Clear();
    }
#endif

    void Add(unsigned char byte)
    {
      mData.push_back(byte);
    }

    template<class InputIterator>
    void Assign(InputIterator first, InputIterator last)
    {
      mChecksum.Clear();
      mData.assign(first, last);
    }

    Elf64_Word NumberOfBytes() const
    {
      return mData.size();
    }

    void
    Dump(SRecType type, Elf64_Addr addr)
    {
      DumpType(type);
      DumpLength(type);
      DumpAddress(type, addr);
      DumpData();
      DumpChecksum();
      mOs << endl;
    }


  private:
    void
    DumpByte(unsigned char data)
    {
      static char c[] = {0,0,0};
      mOs << ToHex(data, c);
      mChecksum.Add(data);
    }

    void DumpType(SRecType type)
    {
      mOs << "S" << type;
    }

    void DumpLength(SRecType type)
    {
      int addrLen(0);
      switch (type)
      {
      case kS0:
      case kS1:
      case kS9:
        addrLen = 2;
        break;

      case kS2:
      case kS8:
        addrLen = 3;
        break;

      case kS3:
      case kS7:
        addrLen = 4;
        break;
      }

      DumpByte((unsigned char) (mData.size() + addrLen + 1));
    }

    void DumpAddress(SRecType type, Elf64_Addr addr)
    {
      switch (type)
      {
        case kS3:
        case kS7:
          DumpByte((addr >> 24) & 0xFF);
          // Fall-through

        case kS2:
        case kS8:
          DumpByte((addr >> 16) & 0xFF);
          // Fall-through

        case kS0:
        case kS1:
        case kS9:
          DumpByte((addr >> 8) & 0xFF);
          DumpByte(addr & 0xFF);
          break;
      }
    }

    void DumpData()
    {
      for_each(mData.begin(), mData.end(),
               bind1st(mem_fun(&RecordDumper::DumpByte), this));
    }

    void DumpChecksum()
    {
      mChecksum.Finalize();
      DumpByte(mChecksum.Get());
    }

  private:
    vector<unsigned char> mData;
    RecordChecksum mChecksum;
    std::ostream & mOs;
  };
} // Namespace


LxElfSaveSRecCmd::
LxElfSaveSRecCmd(string const &         fileName,
                 SRecVariant            variant,
                 unsigned char          len,
                 LxElfCmdOffset const & offset)
  : LxElfSaveCmdBase(fileName, "srec"),
    mVariant(variant),
    mMaxRecordLength(len),
    mOffset(offset)
{
}


void LxElfSaveSRecCmd::
DumpHeader(LxElfFile const & file, std::ostream & os)
{
  std::string filename = GetFilename();
  size_t index = filename.find_last_of('\\');
  if (index == string::npos)
  {
    index = filename.find_last_of('/');
  }

  if (index != string::npos)
    filename = filename.substr(index + 1);

  // Use file name as data bytes
  RecordDumper dumper(os);
  dumper.Assign(filename.begin(), filename.end());
  dumper.Dump(kS0, 0);
}

const SRecVariant & LxElfSaveSRecCmd::
GetVariantToUse(Elf64_Addr addr) const
{
  // Set record type
  if (mVariant.IsAdaptive())
  {
    if (addr > 0xffffff)
      return kS37;
    else if (addr > 0xffff)
      return kS28;
    else
      return kS19;
  }
  else
    return mVariant;
}

Elf64_Addr LxElfSaveSRecCmd::
GetNextVariantAddr(Elf64_Addr addr) const
{
  return addr < 0x10000 ? 0x10000 : 0x1000000;
}

bool LxElfSaveSRecCmd::
DumpData(LxElfFile const &       file,
         Elf64_Addr              startAddr,
         Elf64_Addr              nextAddr,
         LxElfDataBuffer const & bytes,
         bool                    verbose,
         bool                    continueRecord,
         std::ostream &          os)
{
  Elf64_Addr addr = startAddr;
  if (bytes.GetBufLen() > 0)
  {
    const LxAddressRange r(startAddr, startAddr + bytes.GetBufLen() - 1);

    while (r.ContainsAddress(addr))
    {
      if (continueRecord)
        addr = ContinueRecord(file, addr, startAddr, bytes, continueRecord, os);
      else
        addr = DumpRecord(file, addr, nextAddr, startAddr, bytes,
                          continueRecord, os);
    }
    if (continueRecord && nextAddr != addr)
    {
      // we have an unfinished record and the next section will not
      // continue it
      Elf64_Addr usedAddr = mOffset.Modify(addr, file.Is64Bit());
      FinishRecord(usedAddr);
      continueRecord = false;
    }
  }
  return (addr == nextAddr) && continueRecord;
}

static RecordDumper * sDumper = NULL;

Elf64_Addr LxElfSaveSRecCmd::
DumpRecord(LxElfFile const &       file,
           Elf64_Addr              currAddr,
           Elf64_Addr              nextAddr,
           Elf64_Addr              dataStartAddr,
           LxElfDataBuffer const & bytes,
           bool &                  continueRecord,
           std::ostream &          os)
{
  const Elf64_Addr end = dataStartAddr + bytes.GetBufLen() - 1;

  if (!sDumper)
    sDumper = new RecordDumper(255, os);

  // Data record length is the minimum of
  // 1. Nr. of bytes left in the section
  // 2. Nr. of bytes until we need to change variant (if using adaptive)
  // 3. mMaxRecordLength
  Elf64_Word recordLength =
                      min<Elf64_Word>(end - currAddr + 1, mMaxRecordLength);

  if (mVariant.IsAdaptive() && currAddr < 0x1000000)
  {
    // Calculate when we need to change variant
    recordLength =
      min<Elf64_Word>(recordLength, GetNextVariantAddr(currAddr) - currAddr);
  }

  // Add the data bytes
  if (recordLength > 0)
  {
    typedef LxElfDataBuffer::const_iterator CDataIter;
    CDataIter from = bytes.begin() + (currAddr - dataStartAddr);

    // get the bytes
    sDumper->Assign(from, from + recordLength);

    // don't dump yet if the next section will add bytes
    if (   (recordLength < mMaxRecordLength)
        && (currAddr + recordLength == nextAddr))
    {
      continueRecord = true;
      return currAddr + recordLength;
    }

    Elf64_Addr usedAddr = mOffset.Modify(currAddr, file.Is64Bit());
    sDumper->Dump(GetVariantToUse(usedAddr).GetStartType(), usedAddr);
  }

  return currAddr + recordLength;
}

Elf64_Addr LxElfSaveSRecCmd::
ContinueRecord(LxElfFile const &       file,
               Elf64_Addr              currAddr,
               Elf64_Addr              dataStartAddr,
               LxElfDataBuffer const & bytes,
               bool &                  continueRecord,
               std::ostream &          os)
{
  // the buffer contains at least one byte from previously, we just
  // finish this record (or possibly just add to it if we don't have
  // enough bytes)

  // compute number of bytes to add to existing buffer
  Elf64_Addr end       = dataStartAddr + bytes.GetBufLen() - 1;
  Elf64_Word currLen   = sDumper->NumberOfBytes();
  Elf64_Word currAvail = end - currAddr + 1;
  Elf64_Word len       = min<Elf64_Word>(currAvail, mMaxRecordLength - currLen);

  typedef LxElfDataBuffer::const_iterator CDataIter;
  CDataIter  first     = bytes.begin();
  bool       full      = (currLen + len) == mMaxRecordLength;
  Elf64_Addr modded    = currAddr + len;

  // add the bytes
  Elf64_Word i = len;
  while(i--)
    sDumper->Add(*first++);

  if (full)
  {
    Elf64_Word addr = currAddr - currLen;
    addr = mOffset.Modify(addr, file.Is64Bit());
    sDumper->Dump(GetVariantToUse(addr).GetStartType(), addr);
    continueRecord = false;
  }

  return modded;
}

void LxElfSaveSRecCmd::
FinishRecord(Elf64_Addr currAddr)
{
  Elf64_Word len = sDumper->NumberOfBytes();
  if (len)
  {
    sDumper->Dump(GetVariantToUse(currAddr).GetStartType(), currAddr - len);
  }
}

void LxElfSaveSRecCmd::
DumpFooter(LxElfFile const & file, ostream & os)
{
  // Termination record
  // Entry address determines type of end record when using adaptive
  Elf64_Addr entryAddr = file.GetEntryAddr();

  RecordDumper dumper(os);
  dumper.Dump(GetVariantToUse(entryAddr).GetEndType(), entryAddr);
}
