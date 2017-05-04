/* this is blockchain technology.  Well, except without the blocks.
Really it's header chain technology.
The blocks themselves don't really make a chain.  Just the headers do.
*/

package uspv

import (
	"io"
	"log"
	"os"
	"bytes"

	"github.com/adiabat/btcd/blockchain"
	"github.com/adiabat/btcd/chaincfg"
	"github.com/adiabat/btcd/wire"
	"github.com/adiabat/btcd/chaincfg/chainhash"
  "github.com/adiabat/btcd/chaincfg/difficulty"
)

func calcPoW(header wire.BlockHeader, p *chaincfg.Params) chainhash.Hash {
	buf := bytes.NewBuffer(make([]byte, 0, wire.MaxBlockHeaderPayload))
	_ = wire.WriteBlockHeader(buf, 0, &header)
	
	return p.PoWFunction(buf.Bytes())
}

/* checkProofOfWork verifies the header hashes into something
lower than specified by the 4-byte bits field. */
func checkProofOfWork(header wire.BlockHeader, p *chaincfg.Params) bool {
	target := difficulty.CompactToBig(header.Bits)

	// The target must more than 0.  Why can you even encode negative...
	if target.Sign() <= 0 {
		log.Printf("block target %064x is neagtive(??)\n", target.Bytes())
		return false
	}
	// The target must be less than the maximum allowed (difficulty 1)
	if target.Cmp(p.PowLimit) > 0 {
		log.Printf("block target %064x is "+
			"higher than max of %064x", target, p.PowLimit.Bytes())
		return false
	}
	// The header hash must be less than the claimed target in the header.
	blockHash := calcPoW(header, p)
	hashNum := blockchain.HashToBig(&blockHash)
	if hashNum.Cmp(target) > 0 {
		log.Printf("block hash %064x is higher than "+
			"required target of %064x", hashNum, target)
		return false
	}
	return true
}

func CheckHeader(r io.ReadSeeker, height, startheight int32, p *chaincfg.Params) bool {
  var err error
	var cur, prev wire.BlockHeader
	// don't try to verfy the genesis block.  That way madness lies.
	if height == 0 {
		return true
	}

	offsetHeight := height - startheight
	// initial load of headers
	// load epochstart, previous and current.
	// seek to n-1 header
	_, err = r.Seek(int64(80*(offsetHeight-1)), os.SEEK_SET)
	if err != nil {
		log.Printf(err.Error())
		return false
	}
	// read in n-1
	err = prev.Deserialize(r)
	if err != nil {
		log.Printf(err.Error())
		return false
	}
	// seek to curHeight header and read in
	_, err = r.Seek(int64(80*(offsetHeight)), os.SEEK_SET)
	if err != nil {
		log.Printf(err.Error())
		return false
	}
	err = cur.Deserialize(r)
	if err != nil {
		log.Printf(err.Error())
		return false
	}
  
	// get hash of n-1 header
	prevHash := prev.BlockHash()
	// check if headers link together.  That whole 'blockchain' thing.
	if prevHash.IsEqual(&cur.PrevBlock) == false {
		log.Printf("Headers %d and %d don't link.\n",
			height-1, height)
		log.Printf("%s - %s",
			prev.BlockHash().String(), cur.BlockHash().String())
		return false
	}

  // Check that the difficulty bits are correct
  rightBits, err := p.DiffCalcFunction(r, height, startheight, p)
  if err != nil {
    log.Printf("Error calculating Block %d %s difficuly. %s\n",
    height, cur.BlockHash().String(), err.Error())
    return false
  }
  
  if cur.Bits != rightBits {
			log.Printf("Block %d %s incorrect difficuly.  Read %x, expect %x\n",
			height, cur.BlockHash().String(), cur.Bits, rightBits)
			return false
	}
 
	// check if there's a valid proof of work.  That whole "Bitcoin" thing.
	if !checkProofOfWork(cur, p) {
		log.Printf("Block %d Bad proof of work.\n", height)
		return false
	}

	return true // it must have worked if there's no errors and got to the end.
}

/* checkrange verifies a range of headers.  it checks their proof of work,
difficulty adjustments, and that they all link in to each other properly.
This is the only blockchain technology in the whole code base.
Returns false if anything bad happens.  Returns true if the range checks
out with no errors. */
func CheckRange(r io.ReadSeeker, first, last, startHeight int32, p *chaincfg.Params) bool {
	for i := first; i <= last; i++ {
		if !CheckHeader(r, i, startHeight, p) {
			return false
		}
	}
	return true // all good.
}
