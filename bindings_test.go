package silkworm_go

import (
	"testing"
)

func TestInit(t *testing.T) {
	silkworm, err := New(t.TempDir(), "")
	if err != nil {
		t.Error(err)
	}
	err = silkworm.Close()
	if err != nil {
		t.Error(err)
	}
}
