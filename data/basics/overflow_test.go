package basics

import (
	"testing"
	"github.com/stretchr/testify/require"

)


func TestAddUaS(t *testing.T) {

	var ot OverflowTracker
	newval, of := ot.AddUaS(0, 0)
	require.Equal(t, newval, uint64(0))
	require.Equal(t, of, false)

	newval, of = ot.AddUaS(0, -1)
	require.Equal(t, newval, uint64(0))
	require.Equal(t, of, true)


	newval, of = ot.AddUaS(0, 1)
	require.Equal(t, newval, uint64(1))
	require.Equal(t, of, false)

}
