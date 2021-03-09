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

// Class that implements the command for saving an Intel hex file

#include "LxElfSaveIHexCmd.h"
#include "unicode_output.h"

#include "LxElfFile.h"
#include <algorithm>
#include <functional>



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
      // Two's complement of checksum
      mChecksum = 255 - (mChecksum & 0xff);
      mChecksum++;
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
    Dump(int type, Elf64_Addr addr)
    {
      mOs << ":";
      DumpLength();
      DumpOffset(addr);
      DumpType(type);
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

    void DumpLength()
    {
      DumpByte((unsigned char) mData.size());
    }

    void DumpOffset(Elf64_Addr addr)
    {
      DumpByte((unsigned char) ((addr >> 8) & 0xFF));
      DumpByte((unsigned char) (addr & 0xFF));
    }

    void DumpType(int type)
    {
      DumpByte(type);
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



LxElfSaveIHexCmd::
LxElfSaveIHexCmd(const string & fileName, LxElfCmdOffset const & offset)
  : LxElfSaveCmdBase(fileName, "ihex"), mMaxRecordLength(16), mLastLBAAddr(0),
    mOffset(offset)
{
}


void LxElfSaveIHexCmd::
DumpFooter(LxElfFile const & file, ostream & os)
{
  Elf64_Addr entryAddr = file.GetEntryAddr();

   // Only linear address record for now...
  RecordDumper dumper(4, os);
  dumper.Add((entryAddr >> 24) & 0xFF);
  dumper.Add((entryAddr >> 16) & 0xFF);
  dumper.Add((entryAddr >> 8)  & 0xFF);
  dumper.Add((entryAddr)       & 0xFF);
  dumper.Dump(5, 0);

  // EOF record
  RecordDumper eofDumper(os);
  eofDumper.Dump(1, 0);
}


void LxElfSaveIHexCmd::
DumpLBA(std::ostream & os, Elf64_Addr addr)
{
  RecordDumper dumper(2, os);
  dumper.Add(addr >> 24 & 0xFF);
  dumper.Add(addr >> 16 & 0xFF);
  dumper.Dump(4, 0);

  mLastLBAAddr = addr;
}


Elf64_Addr LxElfSaveIHexCmd::
GetNextLBAAddr(Elf64_Addr currAddr)
{
  if (mLastLBAAddr == 0 && currAddr > 0x0000FFFF)
    return currAddr;
  else if (mLastLBAAddr > 0 && (currAddr >> 16) != (mLastLBAAddr >> 16))
    return currAddr;
  else
    return ((currAddr & 0xFFFF0000) + 0x00010000);
}


bool LxElfSaveIHexCmd::
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
      {
        addr = ContinueRecord(file, addr, startAddr, bytes,
                              continueRecord, os);
      }
      else
      {
        addr = DumpRecord(file, addr, nextAddr, startAddr, bytes,
                          continueRecord, os);
      }
    }
    if (continueRecord && nextAddr != addr)
    {
      // we have an unfinished record and the next section will not
      // continue it
      FinishRecord(addr);
      continueRecord = false;
    }
  }
  return (addr == nextAddr) && continueRecord;
}

static RecordDumper * sDumper = NULL;

Elf64_Addr LxElfSaveIHexCmd::
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

  Elf64_Addr phyAddr     = mOffset.Modify(currAddr, file.Is64Bit());
  Elf64_Addr nextLBAAddr = GetNextLBAAddr(phyAddr);
  len                    = min<Elf64_Word>(len, nextLBAAddr - phyAddr);

  typedef LxElfDataBuffer::const_iterator CDataIter;
  CDataIter  first     = bytes.begin();
  bool       full      = (currLen + len) == mMaxRecordLength;
  Elf64_Addr modded    = currAddr + len;

  // add the bytes
  Elf64_Word i = len;
  while(i--)
    sDumper->Add(*first++);

  if (full || ((phyAddr + len) == phyAddr))
  {
    // we have a full record, dump it
    sDumper->Dump(0, currAddr - currLen);
    phyAddr += len;

    // possibly output the next addr adjustment
    if (phyAddr == nextLBAAddr && currAddr <= end)
      DumpLBA(os, phyAddr);

    continueRecord = false;
  }

  return modded;
}


void LxElfSaveIHexCmd::
FinishRecord(Elf64_Addr currAddr)
{
  Elf64_Word len = sDumper->NumberOfBytes();
  if (len)
  {
    sDumper->Dump(0, currAddr - len);
  }
}


Elf64_Addr LxElfSaveIHexCmd::
DumpRecord(LxElfFile const &       file,
           Elf64_Addr              currAddr,
           Elf64_Addr              nextAddr,
           Elf64_Addr              dataStartAddr,
           LxElfDataBuffer const & bytes,
           bool &                  continueRecord,
           std::ostream &          os)
{
  // One past last address
  const Elf64_Addr end = dataStartAddr + bytes.GetBufLen() - 1;

  if (!sDumper)
    sDumper = new RecordDumper(255, os);

  // Data record length is the minimum of
  // 1. Nr. of bytes left in the section
  // 2. Nr. of bytes until we need a new LBA
  // 3. mMaxRecordLength
  Elf64_Word recordLength =
    min<Elf64_Word>(end - currAddr + 1, mMaxRecordLength);

  // Calculate where the next LBA record should be written
  Elf64_Addr phyAddr     = mOffset.Modify(currAddr, file.Is64Bit());
  Elf64_Addr nextLBAAddr = GetNextLBAAddr(phyAddr);
  recordLength = min<Elf64_Word>(recordLength, nextLBAAddr - phyAddr);

  // Add the data bytes
  if (recordLength > 0)
  {
    typedef LxElfDataBuffer::const_iterator CDataIter;
    CDataIter from = bytes.begin() + (currAddr - dataStartAddr);

    sDumper->Assign(from, from + recordLength);

    // don't dump yet if the next section will add bytes
    if (   (recordLength < mMaxRecordLength)
        && (currAddr + recordLength == nextAddr))
    {
      continueRecord = true;
      return currAddr + recordLength;
    }

    sDumper->Dump(0, phyAddr);

    currAddr += recordLength;
    phyAddr  += recordLength;
  }

  // If needed, create an LBA address record.
  if (phyAddr == nextLBAAddr && currAddr <= end)
  {
    DumpLBA(os, phyAddr);
  }

  return currAddr;
}
