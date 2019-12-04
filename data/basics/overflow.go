// Copyright (C) 2019 Algorand, Inc.
// This file is part of go-algorand
//
// go-algorand is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// go-algorand is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with go-algorand.  If not, see <https://www.gnu.org/licenses/>.

package basics

import (
	"math"
)

// OverflowTracker is used to track when an operation causes an overflow
type OverflowTracker struct {
	Overflowed bool
}

func uintAbs(signed int64) (usinged uint64) {
	if(signed < 0) {
		return uint64(-signed)
	}
	return uint64(signed)
}


// OAdd16 adds 2 uint16 values with overflow detection
func OAdd16(a uint16, b uint16) (res uint16, overflowed bool) {
	res = a + b
	overflowed = res < a
	return
}

// OAdd adds 2 values with overflow detection
func OAdd(a uint64, b uint64) (res uint64, overflowed bool) {
	res = a + b
	overflowed = res < a
	return
}

// OSub subtracts b from a with overflow detection
func OSub(a uint64, b uint64) (res uint64, overflowed bool) {
	res = a - b
	overflowed = res > a
	return
}

// OMul multiplies 2 values with overflow detection
func OMul(a uint64, b uint64) (res uint64, overflowed bool) {
	if b == 0 {
		return 0, false
	}

	c := a * b
	if c/b != a {
		return 0, true
	}
	return c, false
}

// MulSaturate multiplies 2 values with saturation on overflow
func MulSaturate(a uint64, b uint64) uint64 {
	res, overflowed := OMul(a, b)
	if overflowed {
		return math.MaxUint64
	}
	return res
}

// Add16 adds 2 uint16 values with overflow detection
func (t *OverflowTracker) Add16(a uint16, b uint16) uint16 {
	res, overflowed := OAdd16(a, b)
	if overflowed {
		t.Overflowed = true
	}
	return res
}

// Add adds 2 values with overflow detection
func (t *OverflowTracker) Add(a uint64, b uint64) uint64 {
	res, overflowed := OAdd(a, b)
	if overflowed {
		t.Overflowed = true
	}
	return res
}

// Sub subtracts b from a with overflow detection
func (t *OverflowTracker) Sub(a uint64, b uint64) uint64 {
	res, overflowed := OSub(a, b)
	if overflowed {
		t.Overflowed = true
	}
	return res
}

// Mul multiplies b from a with overflow detection
func (t *OverflowTracker) Mul(a uint64, b uint64) uint64 {
	res, overflowed := OMul(a, b)
	if overflowed {
		t.Overflowed = true
	}
	return res
}

// OAddA adds 2 MicroAlgos values with overflow tracking
func OAddA(a MicroAlgos, b MicroAlgos) (res MicroAlgos, overflowed bool) {
	res.Raw, overflowed = OAdd(a.Raw, b.Raw)
	return
}


func OAddRep(a Reputation, b Reputation) (res Reputation, overflowed bool) {
	res.Raw, overflowed = OAdd(a.Raw, b.Raw)
	return
}



// OSubA subtracts b from a with overflow tracking
func OSubA(a MicroAlgos, b MicroAlgos) (res MicroAlgos, overflowed bool) {
	res.Raw, overflowed = OSub(a.Raw, b.Raw)
	return
}

// MulAIntSaturate uses MulSaturate to multiply b (int) with a (MicroAlgos)
func MulAIntSaturate(a MicroAlgos, b int) MicroAlgos {
	return MicroAlgos{Raw: MulSaturate(a.Raw, uint64(b))}
}

// AddA adds 2 MicroAlgos values with overflow tracking
func (t *OverflowTracker) AddA(a MicroAlgos, b MicroAlgos) MicroAlgos {
	return MicroAlgos{Raw: t.Add(uint64(a.Raw), uint64(b.Raw))}
}

// AddA adds 2 Reputation values with overflow tracking
func (t *OverflowTracker) AddRep(a Reputation, b Reputation) Reputation {
	return Reputation{Raw: t.Add(uint64(a.Raw), uint64(b.Raw))}
}

func (t *OverflowTracker) SubRep(a Reputation, b Reputation) Reputation {
	return Reputation{Raw: t.Sub(uint64(a.Raw), uint64(b.Raw))}
}


// SubA subtracts b from a with overflow tracking
func (t *OverflowTracker) SubA(a MicroAlgos, b MicroAlgos) MicroAlgos {
	return MicroAlgos{Raw: t.Sub(uint64(a.Raw), uint64(b.Raw))}
}

// AddR adds 2 Round values with overflow tracking
func (t *OverflowTracker) AddR(a Round, b Round) Round {
	return Round(t.Add(uint64(a), uint64(b)))
}

// SubR subtracts b from a with overflow tracking
func (t *OverflowTracker) SubR(a Round, b Round) Round {
	return Round(t.Sub(uint64(a), uint64(b)))
}

// ScalarMulA multiplies an Algo amount by a scalar
func (t *OverflowTracker) ScalarMulA(a MicroAlgos, b uint64) MicroAlgos {
	return MicroAlgos{Raw: t.Mul(a.Raw, b)}
}

func (t *OverflowTracker) AddUaS(unsigned uint64, signed int64) (res uint64, overflowed bool) {
    minres := uint64(100000)
	res = 0
	overflowed = false
	signedAsUnsigned := uintAbs(signed)
	if(signed >= 0) {
		res, overflowed = OAdd(unsigned, signedAsUnsigned)
		if(overflowed) {
			res = unsigned
		}
	} else {
		if(unsigned >= (signedAsUnsigned+minres)) { // 100001 >= 100002, when signed is -2
			res, overflowed = OSub(unsigned, signedAsUnsigned)
		} else {
			res = minres // 0 or 100000
			overflowed = true
		}
	}
	return res, overflowed
}
