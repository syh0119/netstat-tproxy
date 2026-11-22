package constant

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCacheOverrideKeepsConfigAndResourcePaths(t *testing.T) {
	previous := Path
	t.Cleanup(func() { Path = previous })
	home := t.TempDir()
	Path = &path{homeDir: home, configFile: filepath.Join(home, "config.yaml")}
	assert.Equal(t, filepath.Join(home, "cache.db"), filepath.Clean(Path.Cache()))
	SetCacheFile(filepath.Join(home, "root-state", "core-cache.db"))
	assert.Equal(t, filepath.Join(home, "root-state", "core-cache.db"), Path.Cache())
	assert.Equal(t, home, Path.HomeDir())
	assert.Equal(t, filepath.Join(home, "config.yaml"), Path.Config())
	assert.Equal(t, filepath.Join(home, "providers", "rules.yaml"), Path.Resolve(filepath.Join("providers", "rules.yaml")))
	SetCacheFile("")
	assert.Equal(t, filepath.Join(home, "cache.db"), filepath.Clean(Path.Cache()))
}

func TestPath(t *testing.T) {
	assert.False(t, (&path{}).IsSafePath("/usr/share/metacubexd/"))
	assert.True(t, (&path{
		safePaths: []string{"/usr/share/metacubexd"},
	}).IsSafePath("/usr/share/metacubexd/"))

	assert.False(t, (&path{}).IsSafePath("../metacubexd/"))
	assert.True(t, (&path{
		homeDir:   "/usr/share/mihomo",
		safePaths: []string{"/usr/share/metacubexd"},
	}).IsSafePath("../metacubexd/"))
	assert.False(t, (&path{
		homeDir:   "/usr/share/mihomo",
		safePaths: []string{"/usr/share/ycad"},
	}).IsSafePath("../metacubexd/"))

	assert.False(t, (&path{}).IsSafePath("/opt/mykeys/key1.key"))
	assert.True(t, (&path{
		safePaths: []string{"/opt/mykeys"},
	}).IsSafePath("/opt/mykeys/key1.key"))
	assert.True(t, (&path{
		safePaths: []string{"/opt/mykeys/"},
	}).IsSafePath("/opt/mykeys/key1.key"))
	assert.True(t, (&path{
		safePaths: []string{"/opt/mykeys/key1.key"},
	}).IsSafePath("/opt/mykeys/key1.key"))

	assert.True(t, (&path{}).IsSafePath("key1.key"))
	assert.True(t, (&path{}).IsSafePath("./key1.key"))
	assert.True(t, (&path{}).IsSafePath("./mykey/key1.key"))
	assert.True(t, (&path{}).IsSafePath("./mykey/../key1.key"))
	assert.False(t, (&path{}).IsSafePath("./mykey/../../key1.key"))

}
