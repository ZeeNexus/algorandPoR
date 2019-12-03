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

package committee

import (
	"encoding/binary"
	"fmt"
	"math/big"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/committee/sortition"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/protocol"
)

type (
	// An UnauthenticatedCredential is a Credential which has not yet been
	// authenticated.
	UnauthenticatedCredential struct {
		_struct struct{}        `codec:",omitempty,omitemptyarray"`
		Proof   crypto.VrfProof `codec:"pf"`
	}

	// A Credential represents a proof of committee membership.
	//
	// The multiplicity of this membership is specified in the Credential's
	// weight. The VRF output hash (with the owner's address hashed in) is
	// also cached.
	//
	// Upgrades: whether or not domain separation is enabled is cached.
	// If this flag is set, this flag also includes original hashable
	// credential.
	Credential struct {
		_struct struct{}      `codec:",omitempty,omitemptyarray"`
		Weight  uint64        `codec:"wt"`
		VrfOut  crypto.Digest `codec:"h"`

		DomainSeparationEnabled bool               `codec:"ds"`
		Hashable                hashableCredential `codec:"hc"`

		UnauthenticatedCredential
	}

	hashableCredential struct {
		_struct struct{}         `codec:",omitempty,omitemptyarray"`
		RawOut  crypto.VrfOutput `codec:"v"`
		Member  basics.Address   `codec:"m"`
		Iter    uint64           `codec:"i"`
	}
)

// Verify an unauthenticated Credential that was received from the network.
//
// Verify checks if the given credential is a valid proof of membership
// conditioned on the provided committee membership parameters.
//
// If it is, the returned Credential constitutes a proof of this fact.
// Otherwise, an error is returned.
func (cred UnauthenticatedCredential) Verify(proto config.ConsensusParams, m Membership, current basics.Round) (res Credential, err error) {
	selectionKey := m.Record.SelectionID
	ok, vrfOut := selectionKey.Verify(cred.Proof, m.Selector)
    
    // Checks if the member is blacklisted or not (blacklist feature)
	if(current <= m.Record.Blacklisted.Raw){
		logging.Base().Infof("AugAugAug Blacklisted! Round = %v, Blacklist Value = %v", current, m.Record.Blacklisted.Raw)
  		return
	}

	hashable := hashableCredential{
		RawOut: vrfOut,
		Member: m.Record.Addr,
	}

	// Also hash in the address. This is necessary to decorrelate the selection of different accounts that have the same VRF key.
	var h crypto.Digest
	if proto.CredentialDomainSeparationEnabled {
		h = crypto.HashObj(hashable)
	} else {
		h = crypto.Hash(append(vrfOut[:], m.Record.Addr[:]...))
	}

	if !ok {
		err = fmt.Errorf("UnauthenticatedCredential.Verify: could not verify VRF Proof with %v (parameters = %+v, proof = %#v)", selectionKey, m, cred.Proof)
		return
	}

	var weight uint64

	expectedSelection := float64(m.Selector.CommitteeSize(proto))

	userRep := m.Record.RepVotingStake()
	if m.TotalReputation.Raw < userRep.Raw {
			logging.Base().Panicf("UnauthenticatedCredential.Verify: total rep = %v, but user rep = %v", m.TotalReputation, userRep)
	} else {
		weight = sortition.SelectRepBased(userRep.Raw, m.TotalReputation.Raw, expectedSelection, h)
		//logging.Base().Infof("PoR %v %v %v %v", userRep.Raw, m.TotalReputation.Raw, expectedSelection, weight)
	}

	/*
	//userMoney := m.Record.VotingStake()
	if m.TotalMoney.Raw < userMoney.Raw {
		logging.Base().Panicf("UnauthenticatedCredential.Verify: total money = %v, but user money = %v", m.TotalMoney, userMoney)
	} else if m.TotalMoney.IsZero() || expectedSelection == 0 || expectedSelection > float64(m.TotalMoney.Raw) {
		logging.Base().Panicf("UnauthenticatedCredential.Verify: m.TotalMoney %v, expectedSelection %v", m.TotalMoney.Raw, expectedSelection)
	} else if userMoney.IsZero() {
		// weight = 0
	} else {
		//weight = sortition.Select(userMoney.Raw, m.TotalMoney.Raw, expectedSelection, h)
	}
	*/

	if weight == 0 {
		err = fmt.Errorf("UnauthenticatedCredential.Verify: credential has weight 0")
	} else {
		res = Credential{
			UnauthenticatedCredential: cred,
			VrfOut:                    h,
			Weight:                    weight,
			DomainSeparationEnabled:   proto.CredentialDomainSeparationEnabled,
		}
		if res.DomainSeparationEnabled {
			res.Hashable = hashable
		}
	}
	return
}

// MakeCredential creates a new unauthenticated Credential given some selector.
func MakeCredential(secrets *crypto.VrfPrivkey, sel Selector) UnauthenticatedCredential {
	pf, ok := secrets.Prove(sel)
	if !ok {
		logging.Base().Error("Failed to construct a VRF proof -- participation key may be corrupt")
		return UnauthenticatedCredential{}
	}
	return UnauthenticatedCredential{Proof: pf}
}

// Less returns true if this Credential is less than the other credential; false
// otherwise (i.e., >=).
//
// Precondition: both credentials have nonzero weight
func (cred Credential) Less(otherCred Credential) bool {
	i1 := cred.lowestOutput()
	i2 := otherCred.lowestOutput()

	return i1.Cmp(i2) < 0
}

// Equals compares the hash of two Credentials to determine equality and returns
// true if they're equal.
func (cred Credential) Equals(otherCred Credential) bool {
	return cred.VrfOut == otherCred.VrfOut
}

// Selected returns whether this Credential was selected (i.e., if its weight is
// greater than zero).
func (cred Credential) Selected() bool {
	return cred.Weight > 0
}

func (cred Credential) lowestOutput() *big.Int {
	var lowest big.Int

	h1 := cred.VrfOut
	for i := uint64(0); i < cred.Weight; i++ {
		var h crypto.Digest
		if cred.DomainSeparationEnabled {
			cred.Hashable.Iter = i
			h = crypto.HashObj(cred.Hashable)
		} else {
			var h2 crypto.Digest
			binary.BigEndian.PutUint64(h2[:], i)
			h = crypto.Hash(append(h1[:], h2[:]...))
		}

		if i == 0 {
			lowest.SetBytes(h[:])
		} else {
			var temp big.Int
			temp.SetBytes(h[:])
			if temp.Cmp(&lowest) < 0 {
				lowest.Set(&temp)
			}
		}
	}

	return &lowest
}

func (cred hashableCredential) ToBeHashed() (protocol.HashID, []byte) {
	return protocol.Credential, protocol.Encode(cred)
}
