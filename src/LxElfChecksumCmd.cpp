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

/* $Rev: 59839 $ */

// Class that implements the command for calculating a checksum

#include "LxElfChecksumCmd.h"
#include "LxElfException.h"
#include "LxElfFile.h"
#include "LxElfParityCmd.h"
#include "LxMain.h"
#include "unicode_output.h"

#include <algorithm>
#include <functional>
#include <iomanip>
#include <memory>
#include <sstream>
#include <stdexcept>

#include "LxOutput.h"           // last include

// new behavior: array init in constructor
#pragma warning(disable: 4351)


#define ELEMENTS(x) sizeof(x)/sizeof(x[0])

using namespace std;

using unicode_output::ucout;
using unicode_output::ucerr;
using unicode_output::ustring;
using unicode_output::uostream;

ChecksumLog LxElfChecksumCmd::mLog;
ChecksumLog LxElfParityCmd::mLog;

namespace
{
  static
  uint64_t
  mirror(uint64_t orig, uint8_t size)
  {
    uint64_t one = 1, d, r = 0;
    for (d = 0; d < (8 * size); d++)
    {
      if (orig & (one << d))
        r |= ((one << (8 * size - 1)) >> d);
    }
    return r;
  }

  class Mirror
  {
  public:
    Mirror()
    {
      for (int index = 0; index < 256; index++)
        mMirrorByte[index] = (uint8_t)mirror((uint8_t)index, 1);
    }

    uint8_t operator [] (uint32_t index)
    {
      return mMirrorByte[index];
    }

  private:
    uint8_t mMirrorByte[256];
  };

  static
  uint16_t Toggle16(uint16_t val)
  {
    uint8_t mask = 0xFF;
    uint8_t lo = val & mask, hi = (val >> 8) & mask;
    val = (lo << 8) | hi;
    return val;
  }

  static
  uint32_t Toggle32(uint32_t val)
  {
    uint16_t mask = 0xFFFF;
    uint16_t lo = Toggle16(val & mask), hi = Toggle16((val >> 16) & mask);
    val = (lo << 16) | hi;
    return val;
  }

  static
  uint64_t Toggle64(uint64_t val)
  {
    uint32_t mask = 0xFFFFFFFF;
    uint32_t lo = Toggle32(val & mask), hi = Toggle32((val >> 32) & mask);
    val = lo;
    val <<= 32;
    val |= hi;
    return val;
  }

  static
  uint64_t
  ToggleEndianess(uint64_t value, uint8_t len)
  {
    switch (len)
    {
    case 1: value &= 0xFF;                                  break;
    case 2: value = Toggle16(static_cast<uint16_t>(value)); break;
    case 4: value = Toggle32(static_cast<uint32_t>(value)); break;
    case 8: value = Toggle64(value);                        break;
    throw LxMessageException("ToggleEndianess, invalid length");
    }
    return value;
  }

  typedef std::vector<uint32_t> IntVector;

  struct AlgorithmSettings
  {
    AlgorithmSettings(uint64_t       polynomial,
                      uint64_t       startValue,
                      StartValueType startValueType,
                      LxCompl        complement,
                      uint8_t        unitSize,
                      bool           mirrorIn,
                      bool           mirrorOut,
                      bool           reverse,
                      bool           toggle,
                      uint8_t        symbolSize,
                      bool           rSign = false,
                      bool           even = true,
                      uint64_t       flashBase = 0u,
                      IntVector *    parity = 0)
    : mPolynomial(polynomial),
      mStartValue(startValue),
      mStartValueType(startValueType),
      mComplement(complement),
      mMirrorIn(mirrorIn),
      mMirrorOut(mirrorOut),
      mReverse(reverse),
      mUnitSize(unitSize),
      mIndex(0),
      mSymbolSize(symbolSize),
      mRsign(rSign),
      mEven(even),
      mFlashBase(flashBase),
      mParityWords(parity),
      mToggleEndianess(toggle)
    {
    }

    uint64_t       mPolynomial;
    uint64_t       mStartValue;
    StartValueType mStartValueType;
    LxCompl        mComplement;
    uint8_t        mUnitSize;
    uint8_t        mIndex;
    bool           mMirrorIn;
    bool           mMirrorOut;
    bool           mReverse;
    uint8_t        mSymbolSize;
    bool           mRsign;
    bool           mEven;
    bool           mToggleEndianess;
    uint64_t       mFlashBase;
    IntVector *    mParityWords;
  };

  class Algorithm : public LxByteVisitor
  {
  public:

    Algorithm(const AlgorithmSettings & settings);
    virtual ~Algorithm();

    void Calculate(LxAddressRanges const & ranges,
                   LxByteVisitor* pVisitor,
                   LxElfFile & file);

    virtual uint64_t GetSum() const {return mSum;}

  protected:
    virtual void Initialize() = 0;
    virtual void Finalize() = 0;

    virtual void ComplementAndMirror(uint8_t len);

  protected:
    const AlgorithmSettings mSettings;

    uint64_t mSum;
    bool     mBigEndian;
  };

  class CRCAlgo : public Algorithm
  {
  public:
    CRCAlgo(const AlgorithmSettings & settings);

  protected:
    void CalcCRCTable(int size);
    uint8_t PushByte(uint8_t);
    uint8_t PopByte(void);

  protected:
    uint64_t mCRCTable[256];
  private:
    uint8_t  mBuffer[4];
    uint8_t  mIndex;
  };

  class CRCSize1Algo : public CRCAlgo
  {
  public:
    CRCSize1Algo(const AlgorithmSettings & settings);

    virtual void VisitByte(uint8_t b);

  protected:
    virtual void Initialize();
    virtual void Finalize();
  };

  class CRCSize2Algo : public CRCAlgo
  {
  public:
    CRCSize2Algo(const AlgorithmSettings & settings);

    virtual void VisitByte(uint8_t b);

  protected:
    virtual void Initialize();
    virtual void Finalize();
  };

  class CRCSize4Algo : public CRCAlgo
  {
  public:
    CRCSize4Algo(const AlgorithmSettings & settings);

    virtual void VisitByte(uint8_t b);

  protected:
    virtual void Initialize();
    virtual void Finalize();
  };

  class CRCSize8Algo : public CRCAlgo
  {
  public:
    CRCSize8Algo(const AlgorithmSettings & settings);

    virtual void VisitByte(uint8_t b);

  private:
    virtual void Initialize();
    virtual void Finalize();
  };


  class SumWideAlgo : public Algorithm
  {
  public:
    SumWideAlgo(const AlgorithmSettings & settings);

    virtual void VisitByte(uint8_t b);

  protected:
    virtual void Initialize();
    virtual void Finalize();
  };

  class SumTruncAlgo : public SumWideAlgo
  {
  public:
    SumTruncAlgo(const AlgorithmSettings & settings);

  protected:
    virtual void Finalize();
  };


  class Sum32Algo : public Algorithm
  {
  public:
    Sum32Algo(const AlgorithmSettings & settings);

    virtual void VisitByte(uint8_t b);

  protected:
    virtual void Initialize();
    virtual void Finalize();

  private:
    uint32_t mVal;
    uint8_t  mShift;
  };


class ParityAlgorithm : public Algorithm
{
public:
  ParityAlgorithm(uint32_t size, const AlgorithmSettings & settings)
    : Algorithm(settings), mBuffer(), mByteIndex(0),
      mParityWords(settings.mParityWords), mWordIndex(0), mBitIndex(0),
      mWordIndexExceeded(false)
  {
    // size is the size in bytes, the vector uses size in words
    uint32_t words = size >> 2;
    if (size & 0x3)
      ++words;
    mParityWords->resize(words, 0xFFFFFFFF);
  }

  typedef std::vector<uint32_t> IntVector;

protected:
  uint8_t PushByte(uint8_t);
  uint8_t PopByte(void);

protected:
  virtual void SetVisitRange(const LxAddressRange & currentRange, bool reverse);
  virtual void VisitByte(uint8_t b);
  virtual void Initialize()
  {
  }
  virtual void Finalize()
  {
  }

private:
  uint8_t        mBuffer[4];
  uint32_t       mByteIndex;
  IntVector *    mParityWords;
  uint32_t       mWordIndex;
  uint32_t       mBitIndex;
  bool           mWordIndexExceeded;
};

void
ParityAlgorithm::SetVisitRange(const LxAddressRange & range, bool reverse)
{
  if (reverse)
  {
    // reverse == true is associated with checksums only, and is invalid for parity.
    throw LxMessageException("Internal error, parity ranges must be traversed in forward direction.");
  }

  if (0 != (range.GetStart() % mSettings.mUnitSize))
  {
    // not aligned
    ostringstream os;
    os << "The parity range start address must be aligned on a "
       << (int)(mSettings.mUnitSize)
       << " byte boundary.";
    throw LxMessageException(os.str());
  }

  uint64_t wordNum = (range.GetStart() - mSettings.mFlashBase) / mSettings.mUnitSize;

  // Initialise the byte buffer
  mBuffer[0]         = mBuffer[1] = mBuffer[2] = mBuffer[3] = 0;
  mByteIndex         = 0;
  mWordIndexExceeded = false;
  mWordIndex         = static_cast<uint32_t>(wordNum / 32);
  mBitIndex          = static_cast<uint32_t>(wordNum % 32);
}

void
ParityAlgorithm::VisitByte(uint8_t b)
{
  mBuffer[mByteIndex++] = b;

  if (mByteIndex >= mSettings.mUnitSize)
  {
    /* Process word into a parity bit. The bit and byte orders within
     * the word do not matter to the result, and neither do unused
     * bytes in mBuffer (i.e. for byte or halfword parity) as they are
     * set to zero. */
    uint32_t dataWord = (mBuffer[0]        | (mBuffer[1] << 8) |
                        (mBuffer[2] << 16) | (mBuffer[3] << 24));
    // 1 (true) for even parity, 0 (false) for odd parity
    uint32_t parityBit = mSettings.mEven;

    mBuffer[0] = mBuffer[1] = mBuffer[2] = mBuffer[3] = 0;
    mByteIndex = 0;

    /* For every set bit in dataWord, toggle the parity bit */
    while(0u != dataWord)
    {
      parityBit ^= (1u & dataWord); /* no-op if bottom bit is zero */
      dataWord >>= 1;               /* shift the next bit down */
    }

    /* check that we do not access outside the vector of parity bits
     * if mWordIndexExceeded is set the next bit used will be written
     * outside the allocated vector
     */

    if (mWordIndexExceeded)
      throw LxChecksumException(LxChecksumException::kParityWordIndexTooHigh);


    /* Now use the parity bit to toggle the appropriate bit in the parity word.
     * The parity word starts out as all-1s (so that unchanged bits have no effect
     * when written) and gets toggled to zero if parityBit is 1. This is why
     * parityBit is initialised to 1 for even parity, above. If there are an even
     * number of set bits in the dataWord then parityBit will still be 1 and will
     * toggle the bit in nParityWord to zero, i.e. the hardware expects *even* parity.
     */

    if (mSettings.mReverse)
      (*mParityWords)[mWordIndex] ^= (parityBit << (31u - mBitIndex));
    else
      (*mParityWords)[mWordIndex] ^= (parityBit << mBitIndex);

    ++mBitIndex;

    if (mBitIndex > 31)
    {
      mBitIndex = 0;
      ++mWordIndex;
      if (mWordIndex >= mParityWords->size())
        mWordIndexExceeded = true;
    }
  }
}

  Algorithm::
  Algorithm(const AlgorithmSettings & settings)
    : mSum(0), mBigEndian(false), mSettings(settings)
  {
  }

  Algorithm::
  ~Algorithm()
  {
  }

  void Algorithm::
  Calculate(LxAddressRanges const & ranges,
            LxByteVisitor* pVisitor,
            LxElfFile & file)
  {
    mBigEndian = file.IsBigEndian();

    // Initialize algorithm
    Initialize();

    // Process all data
    file.VisitSegmentRanges(*pVisitor, ranges, mSettings.mRsign);

    // Do final processing of the checksum value
    Finalize();
  }

  void Algorithm::
  ComplementAndMirror(uint8_t len)
  {
    switch (mSettings.mComplement)
    {
    case k1sCompl: mSum = ~mSum;     break;
    case k2sCompl: mSum = ~mSum + 1; break;
    default: /* Do nothing */        break;
    }

    if (mSettings.mMirrorOut)
      mSum = mirror(mSum, len);

    if (mSettings.mToggleEndianess)
      mSum = ToggleEndianess(mSum, len);
  }

  /** CRCAlgo ***************************************************************/
  CRCAlgo::
  CRCAlgo(const AlgorithmSettings & settings)
    : Algorithm(settings), mIndex(settings.mIndex), mCRCTable(), mBuffer()
  {
  }

  void CRCAlgo::
  CalcCRCTable(int size)
  {
    uint64_t index = 0, mask = 1;
    mask <<= (size * 8 - 1);
    int left = (size - 1) * 8;

    for (index = 0; index < ELEMENTS(mCRCTable); ++index)
    {
      uint64_t r = index << left;
      for (int i = 0; i < 8; ++i)
      {
        if (r & mask)
          r = (r << 1) ^ mSettings.mPolynomial;
        else
          r <<= 1;
      }
      mCRCTable[index] = r;
    }
  }

  uint8_t CRCAlgo::
  PushByte(uint8_t byte)
  {
    mBuffer[mIndex++] = byte;
    return mIndex;
  }

  uint8_t CRCAlgo::
  PopByte(void)
  {
    return mBuffer[--mIndex];
  }

  /** CRCSize1Algo **********************************************************/
  CRCSize1Algo::
  CRCSize1Algo(const AlgorithmSettings & settings)
    : CRCAlgo(settings)
  {
  }

  void CRCSize1Algo::
  Initialize()
  {
    CalcCRCTable(1);

    if (mSettings.mStartValueType == kPrepended)
    {
      VisitByte(static_cast<uint8_t>(mSettings.mStartValue & 0xFF));
    }
    else
    {
      mSum = static_cast<uint8_t>(mSettings.mStartValue);
    }
  }

  void CRCSize1Algo::
  VisitByte(uint8_t b)
  {
    if (mSettings.mUnitSize == 1)
    {
      uint8_t i = static_cast<uint8_t>(mSum ^ b);
      mSum = mCRCTable[i];
    }
    else
    {
      uint8_t storedBytes = PushByte(b);
      if (storedBytes == mSettings.mUnitSize)
      {
        while (storedBytes--)
        {
          uint8_t i = static_cast<uint8_t>(mSum ^ PopByte());
          mSum = mCRCTable[i];
        }
      }
    }
  }

  void CRCSize1Algo::
  Finalize()
  {
    ComplementAndMirror(1);
    mSum &= 0x00FF;
  }


  /** CRCSize2Algo **********************************************************/
  CRCSize2Algo::
  CRCSize2Algo(const AlgorithmSettings & settings)
  : CRCAlgo(settings)
  {
  }

  void CRCSize2Algo::
  Initialize()
  {
    CalcCRCTable(2);

    if (mSettings.mStartValueType == kPrepended)
    {
      VisitByte(static_cast<uint8_t>((mSettings.mStartValue & 0xFF00) >> 8));
      VisitByte(static_cast<uint8_t>(mSettings.mStartValue & 0xFF));
    }
    else
    {
      mSum = static_cast<uint16_t>(mSettings.mStartValue);
    }
  }

  void CRCSize2Algo::
  VisitByte(uint8_t b)
  {
    if (mSettings.mUnitSize == 1)
    {
      uint8_t i = static_cast<uint8_t>(mSum >> 8);
      mSum = mCRCTable[i ^ b] ^ (mSum << 8);
    }
    else
    {
      uint8_t storedBytes = PushByte(b);
      if (storedBytes == mSettings.mUnitSize)
      {
        while (storedBytes--)
        {
          uint8_t i = static_cast<uint8_t>(mSum >> 8);
          mSum = mCRCTable[i ^ PopByte()] ^ (mSum << 8);
        }
      }

    }
  }

  void CRCSize2Algo::
  Finalize()
  {
    ComplementAndMirror(2);
    mSum &= 0xFFFF;
  }

  /** CRCSize4Algo **********************************************************/
  CRCSize4Algo::
  CRCSize4Algo(const AlgorithmSettings & settings)
    : CRCAlgo(settings)
  {
  }

  void CRCSize4Algo::
  Initialize()
  {
    CalcCRCTable(4);

    if (mSettings.mStartValueType == kPrepended)
    {
      uint32_t data = static_cast<uint32_t>(mSettings.mStartValue);

      for (uint32_t i = 0, mask = 0xFF000000, shift = 24 ;
           i < 4 ;
           ++i, mask >>= 8, shift -= 8)
      {
        VisitByte((data & mask) >> shift);
      }
    }
    else // kInitial or kNone
    {
      mSum = static_cast<uint32_t>(mSettings.mStartValue);
    }
  }

  void CRCSize4Algo::
  VisitByte(uint8_t b)
  {
    if (mSettings.mUnitSize == 1)
    {
      uint8_t i = static_cast<uint8_t>(mSum >> 24);
      mSum = mCRCTable[i ^ b] ^ (mSum << 8);
    }
    else
    {
      uint8_t storedBytes = PushByte(b);
      if (storedBytes == mSettings.mUnitSize)
      {
        while (storedBytes--)
        {
          uint8_t i = static_cast<uint8_t>(mSum >> 24);
          mSum = mCRCTable[i ^ PopByte()] ^ (mSum << 8);
        }
      }
    }
  }

  void CRCSize4Algo::
  Finalize()
  {
    ComplementAndMirror(4);
    mSum &= 0xFFFFFFFF;
  }


  /** CRCSize8Algo **********************************************************/
  CRCSize8Algo::
  CRCSize8Algo(const AlgorithmSettings & settings)
    : CRCAlgo(settings)
  {
  }

  void CRCSize8Algo::
  Initialize()
  {
    CalcCRCTable(8);

    if (mSettings.mStartValueType == kPrepended)
    {
      uint32_t data = mSettings.mStartValue >> 32;
      uint32_t lo   = mSettings.mStartValue & 0xFFFFFFFF;

      for (uint32_t i = 0; i < 2 ; ++i)
      {
        for (uint32_t j = 0, mask = 0xFF000000, shift = 24 ;
             j < 4 ;
             ++j, mask >>= 8, shift -= 8)
        {
          VisitByte((data & mask) >> shift);
        }
        data = lo;
      }
    }
    else // kInitial or kNone
    {
      mSum = mSettings.mStartValue;
    }
  }

  void CRCSize8Algo::
  VisitByte(uint8_t b)
  {
    if (mSettings.mUnitSize == 1)
    {
      uint8_t i = mSum >> 56;
      mSum = mCRCTable[i ^ b] ^ (mSum << 8);
    }
    else
    {
      uint8_t storedBytes = PushByte(b);
      if (storedBytes == mSettings.mUnitSize)
      {
        while (storedBytes--)
        {
          uint8_t i =  mSum >> 56;
          mSum = mCRCTable[i ^ PopByte()] ^ (mSum << 8);
        }
      }

    }
  }

  void CRCSize8Algo::
  Finalize()
  {
    ComplementAndMirror(8);
  }

  /** SumWideAlgo ***********************************************************/
  SumWideAlgo::
  SumWideAlgo(const AlgorithmSettings & settings)
    : Algorithm(settings)
  {
  }

  void SumWideAlgo::
  Initialize()
  {
    mSum = mSettings.mStartValue;
  }

  void SumWideAlgo::
  VisitByte(uint8_t b)
  {
    mSum += b;
  }

  void SumWideAlgo::
  Finalize()
  {
    ComplementAndMirror(mSettings.mSymbolSize);
    mSum &= 0xFFFFFFFF;
  }

  /** SumTruncAlgo **********************************************************/
  SumTruncAlgo::
  SumTruncAlgo(const AlgorithmSettings & settings)
    : SumWideAlgo(settings)
  {
  }

  void SumTruncAlgo::
  Finalize()
  {
    ComplementAndMirror(1);
    mSum &= 0x00FF;
  }


  /** Sum32Algo *************************************************************/
  Sum32Algo::
  Sum32Algo(const AlgorithmSettings & settings)
    : Algorithm(settings), mVal(0), mShift(0)
  {
  }

  void Sum32Algo::
  Initialize()
  {
    mVal   = 0;
    mShift = 0;
    mSum   = 0;
  }

  void Sum32Algo::
  VisitByte(uint8_t b)
  {
    if (mBigEndian)
      mVal |= (((uint32_t) b) << (24 - mShift));
    else
      mVal |= (((uint32_t) b) << mShift);
    mShift += 8;

    if (mShift > 24)
    {
      mSum  += mVal;
      mShift = 0;
      mVal   = 0;
    }
  }

  void Sum32Algo::
  Finalize()
  {
    if (mShift != 0)
      ucerr << "ielftool warning: " << (mShift/8) << " bytes skipped in calculation\n";

    ComplementAndMirror(4);
    mSum &= 0xFFFFFFFF;
  }


  static
  LxByteVisitor*
  createByteVisitor(uint8_t size,
                    Algorithm & a,
                    const AlgorithmSettings & settings);


  static
  Algorithm*
  createCRCAlgorithm(LxAlgo         algorithm,
                     uint8_t        size,
                     const AlgorithmSettings & settings)
  {
    switch (algorithm)
    {
    case kCrc16:
    case kCrc32:
    case kCrc64iso:
    case kCrc64ecma:
    case kCrcPoly:
      switch (size)
      {
      case 1: return new CRCSize1Algo(settings);
      case 2: return new CRCSize2Algo(settings);
      case 4: return new CRCSize4Algo(settings);
      case 8: return new CRCSize8Algo(settings);
      }
      break;

    case kCrcSimple:
      return new SumTruncAlgo(settings);

    case kCrcSimpleWide:
      return new SumWideAlgo(settings);

    case kCrcSimple32:
      return new Sum32Algo(settings);
    }

    return NULL;
  }
}


static
ParityAlgorithm*
createParityAlgorithm(uint32_t        size,
                      const AlgorithmSettings & settings)
{
  return new ParityAlgorithm(size, settings);
}



// LxElfChecksumCmd //////////////////////////////////////////////////////
LxElfChecksumCmd::
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
                 bool                      toggleEndianess)
: mVerbose(false),
  mSize(symSize),
  mUnitSize(unitSize),
  mAlgorithm(algorithm),
  mComplement(complement),
  mMirrorIn(mirrorIn),
  mMirrorOut(mirrorOut),
  mRocksoft(rocksoft),
  mReverse(reverse),
  mRsign(rSign),
  mPolynomial(polynomial),
  mRanges(ranges),
  mSymbol(symbol),
  mSum(0),
  mStartValue(startValue),
  mStartValueType(startValueType),
  mToggleEndianess(toggleEndianess)
{
}


void LxElfChecksumCmd::
Execute(LxElfFile & file, bool verbose)
{
  mVerbose = verbose;

  CalcAndStoreCRC(file);
}

static
bool
IsCrcAlgo(LxAlgo algo)
{
  switch (algo)
  {
  case kCrc16:
  case kCrc32:
  case kCrc64iso:
  case kCrc64ecma:
  case kCrcPoly:
    return true;
  default:
    ;
  }
  return false;
}


void LxElfChecksumCmd::
RemoveChecksumFromRanges(LxAddressRanges & ranges, Elf64_Addr symAddr)
{
  // Exclude the checksum symbol area
  typedef LxAddressRanges::iterator Iter;
  Iter i = find_if<Iter>(ranges.begin(),
                         ranges.end(),
                         bind2nd(mem_fun_ref(&LxAddressRange::ContainsAddress),
                                             symAddr));

  // TODO: Checksum could be covered by several ranges!
  if (i != ranges.end())
  {
    if (i->GetStart() == symAddr)
    {
      // If overlap at start, just move the range start forward
      i->SetStart(symAddr + mSize);
    }
    else
    {
      // We might need to split the range into two.
      Elf64_Addr endAddr = i->GetEnd();
      i->SetEnd(symAddr - 1);
      if (endAddr >= symAddr + mSize)
        ranges.insert(i + 1, LxAddressRange(symAddr + mSize, endAddr));
    }
  }
}

namespace
{
  Elf64_Word GetRangesLength(const LxAddressRanges & ranges)
  {
    Elf64_Word length = 0;
    for (LxAddressRanges::const_iterator i = ranges.begin(), e = ranges.end();
         i != e; ++i)
    {
      length += i->GetLength();
    }
    return length;
  }
}

uint64_t LxElfChecksumCmd::
CalcChecksum(LxAddressRanges const & ranges,
             LxElfFile & file)
{
  AlgorithmSettings settings(mPolynomial,
                             mStartValue,
                             mStartValueType,
                             mComplement,
                             mUnitSize,
                             mMirrorIn,
                             mMirrorOut,
                             mReverse,
                             mToggleEndianess,
                             mSize,
                             mRsign);

  // The length of the ranges must be a multiple of the unit size
  if (GetRangesLength(ranges) % mUnitSize != 0)
  {
    ostringstream os;
    os << "The checksum range must be divisable by "
       << (int) (mUnitSize)
       << " in order to match the checksum unit size.";
    throw LxMessageException(os.str());
  }
  Algorithm* pAlgorithm = createCRCAlgorithm(mAlgorithm, mSize, settings);

  LxByteVisitor* pVisitor = createByteVisitor(mUnitSize, *pAlgorithm, settings);

  pAlgorithm->Calculate(ranges, pVisitor, file);

  uint64_t sum = pAlgorithm->GetSum();

  if (pVisitor != pAlgorithm)
    delete pVisitor;
  delete pAlgorithm;

  return sum;
}


Elf64_Sym LxElfChecksumCmd::
FindSymbol(LxElfFile const & file) const
{
  // Find the string in the string table
  LxElfSection* symScn = file.GetSymbolSection();

  Elf32_Word strIndex = file.GetStringIndex(mSymbol.GetLabel(), symScn->mHdr.sh_link);

  // Use the string index to find the symbol in the symbol table

  pair<Elf64_Sym, Elf32_Word> sw = file.GetSymbol(strIndex);

  uint64_t symbolSize = sw.first.st_size;
  uint8_t symInfo    = sw.first.st_info;

  // the allocated space must match the specified size
  // there are two cases here, if the symbol has a size
  // or not, the case with no info is basically assembler
  // generated, this is not checked further as there is no
  // information to use, the other case has information

  if ((symInfo & 0xF) == STT_OBJECT)
  {
    if (symbolSize && symbolSize < mSize)
    {
      ucerr << "ielftool warning: "
	    << "The checksum symbol '" << ustring(mSymbol.GetLabel()) << "'"
           << " has a reserved size of " << (int)symbolSize
           << " bytes while the checksum command uses a size of "
           << (int)mSize << " bytes." << endl;
    }
  }

  // Symbol must be global
  if ((symInfo >> 4) != STB_GLOBAL)
  {
    throw LxSymbolException(mSymbol.GetLabel(),
                            LxSymbolException::kSymbolNotFound);
  }

  return sw.first;

}

struct LxDisplayRange : unary_function<LxDisplayRange, void>
{
  void operator()(LxAddressRange const & rng)
  {
    ucout << "  0x"
          << rng.GetStart()
          << " - 0x"
          << rng.GetEnd()
          << endl;
  }
};

static
void
OutputRocksoftSummary(uostream &                 o,
                      LxSymbolicAddress const & symbol,
                      bool                      prefixed,
                      uint32_t                  size,
                      uint64_t                  poly,
                      uint64_t                  init,
                      LxAlgo                    algo,
                      bool                      mirrorIn,
                      bool                      mirrorOut,
                      LxCompl                   complement,
                      uint8_t                   unitSize,
                      bool                      toggleEndian)
{
  uint32_t width     = size * 8;
  uint32_t positions = size * 2;
  uint64_t maxMask   = (0ull-1) & ((1ull << width)-1);
  poly &= maxMask;
  init &= maxMask;

  o.setf(ios::dec);
  o << "  Rocksoft Model CRC Algorithm for this checksum:\n"
    << "    NAME :  " << symbol.GetLabel().c_str() << endl
    << "    WIDTH:  " << width << endl;
  o.setf(ios::hex | ios::uppercase | ios::right);
  o.fill('0');
  o << hex << setw(positions)
    << "    POLY:   ";
  if (IsCrcAlgo(algo))
    o << setw(positions) << poly;
  else
    o << "[Not a CRC algorithm]";
  o << endl
    << "    INIT:   " << setw(positions) << init
    << (prefixed ? " [Cannot express prefixed initial value]" : "")
    << endl
    << "    REFIN:  " << (mirrorIn ? "True" : "False") << endl
    << "    REFOUT: " << (mirrorOut ? "True" : "False") << endl
    << "    XOROUT: ";
  switch (complement)
  {
  case kNoCompl: o << setw(positions) << right << hex << 0; break;
  case k1sCompl: o << setw(positions) << right << hex << maxMask; break;
  case k2sCompl: o << "[Cannot express 2's complement]"; break;
  }
  o << endl;

  if (toggleEndian)
  {
    o << "    This checksum uses the x-flag (toggle checksum byte order) "
      "which is not a part of the Rocksoft specification model. It will "
      "thus typically compute a different checksum than a checksum "
      "specified with the same parameters but without byte order "
      "toggling." << endl;
  }

  if (unitSize != 1)
  {
    o << "    This checksum uses a unit size that is not 1. That is not "
      "a part of the Rocksoft specification model. It will "
      "thus typically compute a different checksum than a checksum "
      "specified with the same parameters but with a different checksum "
      "unit size." << endl;
  }




}

// Stores the crc value for the given symbolName
void LxElfChecksumCmd::
CalcAndStoreCRC(LxElfFile & file)
{
  Elf64_Addr symAddr(0);

  // Get absolute address ranges
  LxAddressRanges ranges(LxGetAddressRanges(mRanges, file));

  // Check that the ranges do not overlap
  if (LxRangesOverlap(ranges))
  {
    throw LxChecksumException(LxChecksumException::kChecksumOverlapError);
  }

  // Check if the ranges include a checksum from another cmd
  if (mLog.RangesIncludeOldChecksum(ranges))
  {
    throw LxChecksumException(LxChecksumException::kChecksumOverlapError);
  }

  if (!mSymbol.IsAbsolute())
  {
    // We have been given a symbol for the checksum
    // Find the symbol in the symbol table
    Elf64_Sym sym = FindSymbol(file);

    symAddr = sym.st_value;
  }

  symAddr += mSymbol.GetOffset();

  // Find the section that contains the data for the symbol
  LxElfSection* section = file.GetSectionAtAddr(symAddr);
  if (!section)
  {
    throw LxChecksumException(LxChecksumException::kNoSectionForAddress);
  }

  // Check that the address is contained in a progbits section
  if (!section->IsProgBits())
  {
    throw LxChecksumException(LxChecksumException::kWrongSymbolType);
  }

  LxAddressRange symbolRange(symAddr, symAddr + mSize - 1);

  // Make sure that the checksum fits in the section
  if (!section->GetRange().Contains(symbolRange))
  {
    throw LxChecksumException(LxChecksumException::kSymbolInSeveralSections);
  }

  // Check that the address is not included in other checksum ranges
  if (mLog.ChecksumIsIncludedInOldRanges(symbolRange))
  {
    throw LxChecksumException(LxChecksumException::kChecksumOverlapError);
  }

  // Exclude the checksum symbol area from the ranges
  RemoveChecksumFromRanges(ranges, symAddr);

  // Store this in the cmd parameter history
  mLog.AddSym(symbolRange);
  mLog.AddRanges(ranges);

  // Calculate the checksum
  uint64_t sum = CalcChecksum(ranges, file);

  if (mVerbose)
  {
    ucout << "Calculated the checksum for "
          << hex << "0x"<< symAddr;

    if (!mSymbol.IsAbsolute())
    {
      ucout << " (" << mSymbol.GetLabel().c_str();
      if (mSymbol.GetOffset() != 0)
        ucout << " + " << mSymbol.GetOffset();
      ucout << ")";
    }
    ucout << ": " << hex << "0x" << sum
         << ", the checksummed addresses were:" << endl;
    uint64_t bytes = 0;
    for (auto p : ranges)
    {
      auto start = p.GetStart();
      auto end   = p.GetEnd();
      auto size  = (end - start) + 1;
      bytes += size;
      ucout << "  0x" << start 
            << " - 0x" << end 
            << "     (0x" << size
            << " bytes)" << endl;

    }
    ucout << "  The total number of checksummed bytes was 0x" << bytes << endl;

    if (mRocksoft)
    {
      OutputRocksoftSummary(ucout,
                            mSymbol,
                            mStartValueType == kPrepended,
                            mSize,
                            mPolynomial,
                            mStartValue,
                            mAlgorithm,
                            mMirrorIn,
                            mMirrorOut,
                            mComplement,
                            mUnitSize,
                            mToggleEndianess);
    }
  }

  // Check possible overwrite of bytes, all bytes that are about to be written
  // should be 0, if not we are overwriting some content (misconfiguration,
  // reserve X bytes, write Y bytes, where Y > X?)
  {
    LxElfReader rd(section->mData, symAddr - section->mHdr.sh_addr);
    bool ok = true;
    switch (mSize)
    {
    case 8: if (rd.GetDoubleWord()) ok = false; break;
    case 4: if (rd.GetWord())       ok = false; break;
    case 2: if (rd.GetHalf())       ok = false; break;
    case 1: if (rd.GetByte())       ok = false; break;
    }
    if (!ok)
    {
      Elf64_Word offs = (symAddr - section->mHdr.sh_addr);
      ucerr << "ielftool warning: The location of the checksum symbol '"
	    << ustring(mSymbol.GetLabel()) << "' at offset 0x" << std::hex
           << offs << std::dec << " in section '"
           << ustring(file.GetString(section->mHdr.sh_name,
				     file.GetSectionLabelsIdx()))
           << "' did not contain only zeroes." << endl;
    }
  }

  // Store the checksum value
  StoreChecksum(symAddr - section->mHdr.sh_addr, section, sum);

  if (!mSymbol.IsAbsolute())
  {
    AddDebugSymbol(mSymbol.GetLabel() + "_value", sum, file);
  }
}


void LxElfChecksumCmd::
StoreChecksum(Elf64_Off      scnOffset,
              LxElfSection*  scn,
              uint64_t       sum)
{
  // Store the checksum value
  LxElfWriter wi(scn->mData, scnOffset);
  switch (mSize)
  {
  case 8:  wi.PutDoubleWord(sum);                    break;
  case 4:  wi.PutWord(static_cast<Elf32_Word>(sum)); break;
  case 2:  wi.PutHalf(static_cast<Elf32_Half>(sum)); break;
  case 1:  wi.PutByte(static_cast<uint8_t>(sum));    break;
  default: throw LxChecksumException(LxChecksumException::kWrongSymbolSize);
  }
}

void LxElfChecksumCmd::
AddDebugSymbol(string const &  symbolName,
               uint64_t        value,
               LxElfFile &     file)
{
  // There are two cases here, a 32 (or fewer) bit checksum or a
  // checksum with more than 32 bits. The 33+ bit checksum will be
  // output as two symbols, one containing the 32 least significant
  // bits (named as a normal checksum symbol) and one (named as the
  // original symbol with the suffix "_high") containing the most
  // significant bits
  //
  // Note that these symbols will not be accessible from the
  // application, they are only accessible from the debugger or others
  // that can access the symbol table, if you want to access the
  // checksum XYZ from the application you should access the checksum
  // symbol (XYZ), not try to refer to the debug only symbol XYZ_value
  //

  // Add debug string with suffix "_value"

  LxElfSection* symScn = file.GetSymbolSection();

  bool extraSymbol = value > 0xFFFFFFFF;

  Elf32_Word strIdx = file.AddStringToStringTable(symbolName,
                                                  symScn->mHdr.sh_link);
  Elf32_Word strIdx2 = 0;
  if (extraSymbol)
    strIdx2 = file.AddStringToStringTable(symbolName + "_high",
                                          symScn->mHdr.sh_link);

  // Add a symbol for the value
  Elf64_Sym dbgSym;
  dbgSym.st_name  = strIdx;
  dbgSym.st_value = static_cast<Elf32_Word>(value);
  dbgSym.st_size  = 0;
  dbgSym.st_info  = (STB_GLOBAL<<4) | (STT_OBJECT);
  dbgSym.st_other = 0;
  dbgSym.st_shndx = SHN_ABS;

  file.AddSymbol(dbgSym);

  if (extraSymbol)
  {
    Elf64_Sym dbgSym2;
    dbgSym2.st_name  = strIdx2;
    dbgSym2.st_value = value >> 32;
    dbgSym2.st_size  = 0;
    dbgSym2.st_info  = (STB_GLOBAL<<4) | (STT_OBJECT);
    dbgSym2.st_other = 0;
    dbgSym2.st_shndx = SHN_ABS;

    file.AddSymbol(dbgSym2);
  }
}



// LxElfParityCmd //////////////////////////////////////////////////////
LxElfParityCmd::
LxElfParityCmd(uint32_t                   symSize,
               bool                       even,
               bool                       reverse,
               LxSymbolicRanges const &   ranges,
               LxSymbolicAddress const &  symbol,
               uint32_t                   unitSize,
               LxSymbolicAddress const &  flashBase)
  : mVerbose(false),
    mSize(symSize),
    mUnitSize(unitSize),
    mEven(even),
    mReverse(reverse),
    mRanges(ranges),
    mSymbol(symbol),
    mFlashBase(flashBase)
{
}


void LxElfParityCmd::
Execute(LxElfFile & file, bool verbose)
{
  mVerbose = verbose;

  CalcAndStoreParity(file);
}


void LxElfParityCmd::
RemoveParityFromRanges(LxAddressRanges & ranges, Elf64_Addr symAddr)
{
  // Exclude the Parity symbol area
  typedef LxAddressRanges::iterator Iter;
  Iter i = find_if<Iter>(ranges.begin(),
                         ranges.end(),
                         bind2nd(mem_fun_ref(&LxAddressRange::ContainsAddress),
                                             symAddr));

  // TODO: Parity could be covered by several ranges!
  if (i != ranges.end())
  {
    if (i->GetStart() == symAddr)
    {
      // If overlap at start, just move the range start forward
      i->SetStart(symAddr + mSize);
    }
    else
    {
      // We might need to split the range into two.
      Elf64_Addr endAddr = i->GetEnd();
      i->SetEnd(symAddr - 1);
      if (endAddr >= symAddr + mSize)
        ranges.insert(i + 1, LxAddressRange(symAddr + mSize, endAddr));
    }
  }
}

void
LxElfParityCmd::
CalcParity(LxAddressRanges const & ranges,
           LxElfFile &             file,
           IntVector &             parityWords)
{
  AlgorithmSettings settings(0u,
                             0u,
                             kNone,
                             kNoCompl,
                             mUnitSize,
                             false,
                             false,
                             mReverse,
                             false,
                             mSize,
                             false,
                             mEven,
                             LxGetAddress(mFlashBase, file),
                             &parityWords);

  // The length of the ranges must be a multiple of the input size for the
  // Parity algorithm.
  if (GetRangesLength(ranges) % mUnitSize != 0)
  {
    ostringstream os;
    os << "The Parity range must be divisable by "
       << (int) (mUnitSize)
       << " in order to match the Parity algorithm.";
    throw LxMessageException(os.str());
  }

  if (GetRangesLength(ranges) % mUnitSize != 0)
  {
    ostringstream os;
    os << "The Parity range must be divisable by "
       << (int) (mUnitSize)
       << " in order to match the Parity unit size.";
    throw LxMessageException(os.str());
  }

  ParityAlgorithm* pAlgorithm = createParityAlgorithm(mSize, settings);

  LxByteVisitor* pVisitor = createByteVisitor(mUnitSize, *pAlgorithm, settings);

  pAlgorithm->Calculate(ranges, pVisitor, file);

  if (pVisitor != pAlgorithm)
    delete pVisitor;
  delete pAlgorithm;
}


Elf64_Sym LxElfParityCmd::
FindSymbol(LxElfFile const & file) const
{
  // Find the string in the string table
  LxElfSection* symScn = file.GetSymbolSection();

  Elf32_Word strIndex = file.GetStringIndex(mSymbol.GetLabel(),
                                            symScn->mHdr.sh_link);

  // Use the string index to find the symbol in the symbol table
  try
  {
    pair<Elf64_Sym, Elf32_Word> sw = file.GetSymbol(strIndex);

    // Symbol must be global
    if ((sw.first.st_info >> 4) != STB_GLOBAL)
    {
      throw LxChecksumException(LxChecksumException::kWrongSymbolType);
    }

    return sw.first;

  }
  catch(...)
  {
    throw LxSymbolException(mSymbol.GetLabel(),
                            LxSymbolException::kSymbolNotFound);
  }
}

// Stores the parity value for the given symbolName
void LxElfParityCmd::
CalcAndStoreParity(LxElfFile & file)
{
  Elf64_Addr symAddr(0);

  // Get absolute address ranges
  LxAddressRanges ranges(LxGetAddressRanges(mRanges, file));

  // Check that the ranges do not overlap
  if (LxRangesOverlap(ranges))
  {
    throw LxChecksumException(LxChecksumException::kChecksumOverlapError);
  }

  // Check if the ranges include a checksum from another cmd
  if (mLog.RangesIncludeOldChecksum(ranges))
  {
    throw LxChecksumException(LxChecksumException::kChecksumOverlapError);
  }

  if (!mSymbol.IsAbsolute())
  {
    // We have been given a symbol for the checksum
    // Find the symbol in the symbol table
    Elf64_Sym sym = FindSymbol(file);

    symAddr = sym.st_value;
  }

  symAddr += mSymbol.GetOffset();

  // Find the section that contains the data for the symbol
  LxElfSection* section = file.GetSectionAtAddr(symAddr);
  if (!section)
  {
    throw LxChecksumException(LxChecksumException::kNoSectionForAddress);
  }

  // Check that the address is contained in a progbits section
  if (!section->IsProgBits())
  {
    throw LxChecksumException(LxChecksumException::kWrongSymbolType);
  }

  LxAddressRange symbolRange(symAddr, symAddr + mSize - 1);

  // Make sure that the checksum fits in the section
  if (!section->GetRange().Contains(symbolRange))
  {
    throw LxChecksumException(LxChecksumException::kSymbolInSeveralSections);
  }

  // Check that the address is not included in other checksum ranges
  if (mLog.ChecksumIsIncludedInOldRanges(symbolRange))
  {
    throw LxChecksumException(LxChecksumException::kChecksumOverlapError);
  }

  // Exclude the Parity symbol area from the ranges
  RemoveParityFromRanges(ranges, symAddr);

  // Store this in the cmd parameter history
  mLog.AddSym(symbolRange);
  mLog.AddRanges(ranges);

  // Calculate the Parity
  IntVector parityWords;
  CalcParity(ranges, file, parityWords);

  if (mVerbose)
  {
    ucout << "Calculated the parity for "
          << hex << "0x"<< symAddr;

    if (!mSymbol.IsAbsolute())
    {
      ucout << " (" << mSymbol.GetLabel().c_str();
      if (mSymbol.GetOffset() != 0)
        ucout << " + " << mSymbol.GetOffset();
      ucout << "), the paritied addresses were:" << endl;
      for_each(ranges.begin(), ranges.end(), LxDisplayRange());
    }

    ucout << endl;
  }

  // Store the Parity value
  StoreParity(symAddr - section->mHdr.sh_addr, section, parityWords);
}


void LxElfParityCmd::
StoreParity(Elf64_Off           scnOffset,
            LxElfSection*       scn,
            const IntVector &   parityWords)
{
  // Store the Parity value
  LxElfWriter wi(scn->mData, scnOffset);
  const size_t wordCount = parityWords.size();

  for (size_t i = 0;
       i < wordCount;
       ++i)
  {
    wi.PutWord(static_cast<Elf32_Word>(parityWords[i]));
  }
}

namespace
{
  class FilterByteVisitor : public LxByteVisitor
  {
  public:
    FilterByteVisitor(LxByteVisitor & next) : mNext(next) {}
    virtual void SetVisitRange(const LxAddressRange & currentRange, bool reverse)
    {
      mNext.SetVisitRange(currentRange, reverse);
    };
  protected:
    LxByteVisitor & mNext;
  };

  class MirroredByteVisitor : public FilterByteVisitor
  {
  public:
    MirroredByteVisitor(LxByteVisitor & next) : FilterByteVisitor(next) {}

    virtual void VisitByte(uint8_t b)
    {
      mNext.VisitByte(mByteMirror[b]);
    }

  private:
    Mirror mByteMirror;
  };

  class ReversedByteVisitor : public FilterByteVisitor
  {
  public:
    ReversedByteVisitor(int size, LxByteVisitor & next)
      : FilterByteVisitor(next), mSize(size), mBuffer(), mBufLength(0) {}

    virtual void VisitByte(uint8_t b)
    {
      if (mBufLength < mSize)
        mBuffer[mBufLength++] = b;

      if (mBufLength == mSize)
      {
        while (mBufLength > 0)
        {
          mNext.VisitByte(mBuffer[--mBufLength]);
        }
      }
    }

    virtual void VisitEnd()
    {
      if (mBufLength > 0)
      {
        ucerr << "ielftool warning: "
             << mBufLength << " bytes skipped in calculation\n";
      }
    }

    virtual Elf32_Word getNrOfBufferBytes() const
    {
      return mBufLength;
    }

  private:
    const int mSize;
    uint8_t   mBuffer[8];
    uint8_t   mBufLength;
  };

  class ReversedMirroredByteVisitor : public ReversedByteVisitor
  {
  public:
    ReversedMirroredByteVisitor(int size, LxByteVisitor & next)
      : ReversedByteVisitor(size, next) {}

    virtual void VisitByte(uint8_t b)
    {
      ReversedByteVisitor::VisitByte(mByteMirror[b]);
    }

  private:
    Mirror mByteMirror;
  };

  static
  LxByteVisitor*
  createByteVisitor(uint8_t size,
                    Algorithm & a,
                    const AlgorithmSettings & settings)
  {
    if (settings.mReverse && size > 1)
    {
      if (settings.mMirrorIn)
        return new ReversedMirroredByteVisitor(size, a);
      else
        return new ReversedByteVisitor(size, a);
    }
    else
    {
      if (settings.mMirrorIn)
        return new MirroredByteVisitor(a);
      else
        return &a;
    }
  }
}

void ChecksumLog::
AddSym(const LxAddressRange & symRange)
{
  mSyms.push_back(symRange);
}

void ChecksumLog::
AddRanges(const LxAddressRanges & ranges)
{
  mRanges.push_back(ranges);
}


namespace
{
  bool Intersects(LxAddressRange a, LxAddressRange b)
  {
    return a.Intersects(b);
  }

  bool RangesIntersectRange(LxAddressRanges a, LxAddressRange b)
  {
    return find_if(a.begin(),
                   a.end(),
                   bind2nd(ptr_fun(Intersects), b)) != a.end();
  }

  bool RangeIntersectRanges(LxAddressRange a, LxAddressRanges b)
  {
    return find_if(b.begin(),
                   b.end(),
                   bind2nd(ptr_fun(Intersects), a)) != b.end();
  }
}

bool ChecksumLog::
RangesIncludeOldChecksum(LxAddressRanges const & ranges) const
{
  // Check if the ranges include old checksum symbols
  return find_if(mSyms.begin(),
                 mSyms.end(),
                 bind2nd(ptr_fun(RangeIntersectRanges),
                         ranges)) != mSyms.end();
}

bool ChecksumLog::
ChecksumIsIncludedInOldRanges(const LxAddressRange & symbolRange) const
{
  // Check if this symbol is included in older ranges
  return find_if(mRanges.begin(),
                 mRanges.end(),
                 bind2nd(ptr_fun(RangesIntersectRange),
                         symbolRange)) != mRanges.end();
}
