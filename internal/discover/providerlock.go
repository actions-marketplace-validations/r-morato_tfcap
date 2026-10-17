package discover

import (
	"os"
	"path/filepath"
	"sort"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/zclconf/go-cty/cty"

	"github.com/r-morato/tfcap/internal/model"
)

// readProviderLock parses .terraform.lock.hcl in dir. A missing file is
// not an error.
func readProviderLock(dir string) ([]model.ProviderLock, error) {
	src, err := os.ReadFile(filepath.Join(dir, ".terraform.lock.hcl"))
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	f, diags := hclsyntax.ParseConfig(src, ".terraform.lock.hcl", hcl.InitialPos)
	if diags.HasErrors() {
		return nil, diags
	}
	body := f.Body.(*hclsyntax.Body)
	var out []model.ProviderLock
	for _, b := range body.Blocks {
		if b.Type != "provider" || len(b.Labels) != 1 {
			continue
		}
		p := model.ProviderLock{Address: b.Labels[0], Line: b.TypeRange.Start.Line}
		if at, ok := b.Body.Attributes["version"]; ok {
			if v, d := at.Expr.Value(nil); !d.HasErrors() && v.Type() == cty.String {
				p.Version = v.AsString()
			}
		}
		if at, ok := b.Body.Attributes["hashes"]; ok {
			if v, d := at.Expr.Value(nil); !d.HasErrors() && v.CanIterateElements() {
				for it := v.ElementIterator(); it.Next(); {
					if _, h := it.Element(); h.Type() == cty.String {
						p.Hashes = append(p.Hashes, h.AsString())
					}
				}
			}
		}
		sort.Strings(p.Hashes)
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Address < out[j].Address })
	return out, nil
}
