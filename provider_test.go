package goth_test

import (
	"sync"
	"testing"

	"github.com/markbates/goth"
	"github.com/markbates/goth/providers/faux"
	"github.com/stretchr/testify/assert"
)

func Test_UseProviders(t *testing.T) {
	a := assert.New(t)

	provider := &faux.Provider{}
	goth.UseProviders(provider)
	a.Equal(len(goth.GetProviders()), 1)
	a.Equal(goth.GetProviders()[provider.Name()], provider)
	goth.ClearProviders()
}

func Test_GetProvider(t *testing.T) {
	a := assert.New(t)

	provider := &faux.Provider{}
	goth.UseProviders(provider)

	p, err := goth.GetProvider(provider.Name())
	a.NoError(err)
	a.Equal(p, provider)

	_, err = goth.GetProvider("unknown")
	a.Error(err)
	a.Equal(err.Error(), "no provider for unknown exists")
	goth.ClearProviders()
}

// namedProvider returns a faux provider registered under the given name.
func namedProvider(name string) goth.Provider {
	return &renamedProvider{name: name}
}

type renamedProvider struct {
	faux.Provider
	name string
}

func (p *renamedProvider) Name() string { return p.name }

func Test_ReplaceProviders(t *testing.T) {
	a := assert.New(t)
	defer goth.ClearProviders()

	old := namedProvider("old")
	kept := namedProvider("kept")
	goth.UseProviders(old, kept)

	fresh := namedProvider("fresh")
	dupFirst := namedProvider("dup")
	dupLast := namedProvider("dup")
	goth.ReplaceProviders(fresh, dupFirst, dupLast)

	a.Len(goth.GetProviders(), 2)
	_, err := goth.GetProvider("old")
	a.Error(err)
	_, err = goth.GetProvider("kept")
	a.Error(err)
	got, err := goth.GetProvider("fresh")
	a.NoError(err)
	a.Same(fresh, got)
	got, err = goth.GetProvider("dup")
	a.NoError(err)
	a.Same(dupLast, got)

	goth.ReplaceProviders()
	a.Empty(goth.GetProviders())
}

func Test_ReplaceProviders_NeverExposesMissingProvider(t *testing.T) {
	const (
		readers  = 8
		replaces = 2000
	)
	defer goth.ClearProviders()

	stable := namedProvider("stable")
	goth.ReplaceProviders(stable)

	done := make(chan struct{})
	var wg sync.WaitGroup
	missing := make(chan error, readers)
	for range readers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-done:
					return
				default:
				}
				if _, err := goth.GetProvider("stable"); err != nil {
					missing <- err
					return
				}
			}
		}()
	}

	for i := range replaces {
		extra := namedProvider("extra")
		if i%2 == 0 {
			goth.ReplaceProviders(stable, extra)
		} else {
			goth.ReplaceProviders(stable)
		}
	}
	close(done)
	wg.Wait()

	select {
	case err := <-missing:
		t.Fatalf("reader saw the provider missing during a replace: %v", err)
	default:
	}
}

func Test_GetProviders_ReturnsSnapshot(t *testing.T) {
	a := assert.New(t)
	defer goth.ClearProviders()

	first := namedProvider("first")
	goth.ReplaceProviders(first)

	snap := goth.GetProviders()
	goth.UseProviders(namedProvider("second"))
	a.Len(snap, 1, "a later UseProviders must not change an earlier result")
	a.NotContains(snap, "second")

	delete(snap, "first")
	got, err := goth.GetProvider("first")
	a.NoError(err, "mutating the result must not change the registry")
	a.Same(first, got)
}
