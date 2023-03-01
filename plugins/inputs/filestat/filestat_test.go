// +build !windows

// TODO: Windows - should be enabled for Windows when super asterisk is fixed on Windows
// https://github.com/influxdata/telegraf/issues/6248

package filestat

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/influxdata/telegraf/testutil"
)

var (
	testdataDir = getTestdataDir()
)

func TestGatherNoMd5(t *testing.T) {
	fs := NewFileStat()
	fs.Log = testutil.Logger{}
	fs.Files = []string{
		filepath.Join(testdataDir, "log1.log"),
		filepath.Join(testdataDir, "log2.log"),
		filepath.Join(testdataDir, "non_existent_file"),
	}

	acc := testutil.Accumulator{}
	acc.GatherError(fs.Gather)

	tags1 := map[string]string{
		"file": filepath.Join(testdataDir, "log1.log"),
		"use_match": "0",
	}
	require.True(t, acc.HasPoint("filestat", tags1, "size_bytes", int64(0)))
	require.True(t, acc.HasPoint("filestat", tags1, "exists", int64(1)))

	tags2 := map[string]string{
		"file": filepath.Join(testdataDir, "log2.log"),
		"use_match": "0",
	}
	require.True(t, acc.HasPoint("filestat", tags2, "size_bytes", int64(0)))
	require.True(t, acc.HasPoint("filestat", tags2, "exists", int64(1)))

	tags3 := map[string]string{
		"file": filepath.Join(testdataDir, "non_existent_file"),
		"use_match": "0",
	}
	require.True(t, acc.HasPoint("filestat", tags3, "exists", int64(0)))
}

func TestGatherExplicitFiles(t *testing.T) {
	fs := NewFileStat()
	fs.Log = testutil.Logger{}
	fs.Md5 = true
	fs.Files = []string{
		filepath.Join(testdataDir, "log1.log"),
		filepath.Join(testdataDir, "log2.log"),
		filepath.Join(testdataDir, "non_existent_file"),
	}

	acc := testutil.Accumulator{}
	acc.GatherError(fs.Gather)

	tags1 := map[string]string{
		"file": filepath.Join(testdataDir, "log1.log"),
		"use_match": "0",
	}
	require.True(t, acc.HasPoint("filestat", tags1, "size_bytes", int64(0)))
	require.True(t, acc.HasPoint("filestat", tags1, "exists", int64(1)))
	require.True(t, acc.HasPoint("filestat", tags1, "md5_sum", "d41d8cd98f00b204e9800998ecf8427e"))

	tags2 := map[string]string{
		"file": filepath.Join(testdataDir, "log2.log"),
		"use_match": "0",
	}
	require.True(t, acc.HasPoint("filestat", tags2, "size_bytes", int64(0)))
	require.True(t, acc.HasPoint("filestat", tags2, "exists", int64(1)))
	require.True(t, acc.HasPoint("filestat", tags2, "md5_sum", "d41d8cd98f00b204e9800998ecf8427e"))

	tags3 := map[string]string{
		"file": filepath.Join(testdataDir, "non_existent_file"),
		"use_match": "0",
	}
	require.True(t, acc.HasPoint("filestat", tags3, "exists", int64(0)))
}

func TestNonExistentFile(t *testing.T) {
	fs := NewFileStat()
	fs.Log = testutil.Logger{}
	fs.Md5 = true
	fs.Files = []string{
		"/non/existant/file",
	}
	acc := testutil.Accumulator{}
	require.NoError(t, acc.GatherError(fs.Gather))

	acc.AssertContainsFields(t, "filestat", map[string]interface{}{"exists": int64(0)})
	assert.False(t, acc.HasField("filestat", "error"))
	assert.False(t, acc.HasField("filestat", "md5_sum"))
	assert.False(t, acc.HasField("filestat", "size_bytes"))
	assert.False(t, acc.HasField("filestat", "modification_time"))
}

func TestNonExistentCrcFile(t *testing.T) {
	fs := NewFileStat()
	fs.Log = testutil.Logger{}
	fs.Md5Crc = true
	fs.Files = []string{
		"/non/existant/file",
	}
	acc := testutil.Accumulator{}
	require.NoError(t, acc.GatherError(fs.Gather))

	acc.AssertContainsFields(t, "filestat", map[string]interface{}{"exists": int64(0)})
	assert.False(t, acc.HasField("filestat", "error"))
	assert.False(t, acc.HasField("filestat", "md5_crc"))
	assert.False(t, acc.HasField("filestat", "size_bytes"))
	assert.False(t, acc.HasField("filestat", "modification_time"))
}

func TestGatherGlob(t *testing.T) {
	fs := NewFileStat()
	fs.Log = testutil.Logger{}
	fs.Md5 = true
	fs.UseMatch = false
	fs.Files = []string{
		filepath.Join(testdataDir, "*.log"),
	}

	acc := testutil.Accumulator{}
	acc.GatherError(fs.Gather)

	tags1 := map[string]string{
		"file": filepath.Join(testdataDir, "log1.log"),
		"use_match": "0",
	}
	require.True(t, acc.HasPoint("filestat", tags1, "size_bytes", int64(0)))
	require.True(t, acc.HasPoint("filestat", tags1, "exists", int64(1)))
	require.True(t, acc.HasPoint("filestat", tags1, "md5_sum", "d41d8cd98f00b204e9800998ecf8427e"))

	tags2 := map[string]string{
		"file": filepath.Join(testdataDir, "log2.log"),
		"use_match": "0",
	}
	require.True(t, acc.HasPoint("filestat", tags2, "size_bytes", int64(0)))
	require.True(t, acc.HasPoint("filestat", tags2, "exists", int64(1)))
	require.True(t, acc.HasPoint("filestat", tags2, "md5_sum", "d41d8cd98f00b204e9800998ecf8427e"))
}

func TestGatherMatchGlob(t *testing.T) {
	fs := NewFileStat()
	fs.Log = testutil.Logger{}
	fs.Md5 = true
	fs.Md5Crc = true
	fs.UseMatch = true
	fs.MatchCmd = "grep test"
	fs.Files = []string{
		filepath.Join(testdataDir, "*.log"),
	}

	acc := testutil.Accumulator{}
	acc.GatherError(fs.Gather)

	tags1 := map[string]string{
		"file": filepath.Join(testdataDir, "log1.log"),
		"use_match": "1",
	}
	require.True(t, acc.HasPoint("filestat", tags1, "size_bytes", int64(0)))
	require.True(t, acc.HasPoint("filestat", tags1, "exists", int64(1)))
	require.True(t, acc.HasPoint("filestat", tags1, "md5_crc", int64(991388534)))
	require.True(t, acc.HasPoint("filestat", tags1, "is_match", int64(0)))

	tags2 := map[string]string{
		"file": filepath.Join(testdataDir, "log2.log"),
		"use_match": "1",
	}
	require.True(t, acc.HasPoint("filestat", tags2, "size_bytes", int64(0)))
	require.True(t, acc.HasPoint("filestat", tags2, "exists", int64(1)))
	require.True(t, acc.HasPoint("filestat", tags2, "md5_crc", int64(991388534)))
	require.True(t, acc.HasPoint("filestat", tags2, "is_match", int64(0)))
}

func TestGatherSuperAsterisk(t *testing.T) {
	fs := NewFileStat()
	fs.Log = testutil.Logger{}
	fs.Md5 = true
	fs.Files = []string{
		filepath.Join(testdataDir, "**"),
	}

	acc := testutil.Accumulator{}
	acc.GatherError(fs.Gather)

	tags1 := map[string]string{
		"file": filepath.Join(testdataDir, "log1.log"),
		"use_match": "0",
	}
	require.True(t, acc.HasPoint("filestat", tags1, "size_bytes", int64(0)))
	require.True(t, acc.HasPoint("filestat", tags1, "exists", int64(1)))
	require.True(t, acc.HasPoint("filestat", tags1, "md5_sum", "d41d8cd98f00b204e9800998ecf8427e"))

	tags2 := map[string]string{
		"file": filepath.Join(testdataDir, "log2.log"),
		"use_match": "0",
	}
	require.True(t, acc.HasPoint("filestat", tags2, "size_bytes", int64(0)))
	require.True(t, acc.HasPoint("filestat", tags2, "exists", int64(1)))
	require.True(t, acc.HasPoint("filestat", tags2, "md5_sum", "d41d8cd98f00b204e9800998ecf8427e"))

	tags3 := map[string]string{
		"file": filepath.Join(testdataDir, "test.conf"),
		"use_match": "0",
	}
	require.True(t, acc.HasPoint("filestat", tags3, "size_bytes", int64(104)))
	require.True(t, acc.HasPoint("filestat", tags3, "exists", int64(1)))
	require.True(t, acc.HasPoint("filestat", tags3, "md5_sum", "5a7e9b77fa25e7bb411dbd17cf403c1f"))
}

func TestGatherMatchSuperAsterisk(t *testing.T) {
	fs := NewFileStat()
	fs.Log = testutil.Logger{}
	fs.Md5 = true
	fs.Md5Crc = false
	fs.UseMatch = true
	fs.MatchCmd = "grep 'option'"
	fs.Files = []string{
		filepath.Join(testdataDir, "**"),
	}

	acc := testutil.Accumulator{}
	acc.GatherError(fs.Gather)

	tags1 := map[string]string{
		"file": filepath.Join(testdataDir, "log1.log"),
		"use_match": "1",
	}
	require.True(t, acc.HasPoint("filestat", tags1, "size_bytes", int64(0)))
	require.True(t, acc.HasPoint("filestat", tags1, "exists", int64(1)))
	require.True(t, acc.HasPoint("filestat", tags1, "is_match", int64(0)))
	require.True(t, acc.HasPoint("filestat", tags1, "md5_sum", "d41d8cd98f00b204e9800998ecf8427e"))

	tags2 := map[string]string{
		"file": filepath.Join(testdataDir, "log2.log"),
		"use_match": "1",
	}
	require.True(t, acc.HasPoint("filestat", tags2, "size_bytes", int64(0)))
	require.True(t, acc.HasPoint("filestat", tags2, "exists", int64(1)))
	require.True(t, acc.HasPoint("filestat", tags2, "is_match", int64(0)))
	require.True(t, acc.HasPoint("filestat", tags2, "md5_sum", "d41d8cd98f00b204e9800998ecf8427e"))

	tags3 := map[string]string{
		"file": filepath.Join(testdataDir, "test.conf"),
		"use_match": "1",
	}
	require.True(t, acc.HasPoint("filestat", tags3, "size_bytes", int64(104)))
	require.True(t, acc.HasPoint("filestat", tags3, "exists", int64(1)))
	require.True(t, acc.HasPoint("filestat", tags3, "is_match", int64(1)))
	require.True(t, acc.HasPoint("filestat", tags3, "md5_sum", "5a7e9b77fa25e7bb411dbd17cf403c1f"))
}

func TestModificationTime(t *testing.T) {
	fs := NewFileStat()
	fs.Log = testutil.Logger{}
	fs.Files = []string{
		filepath.Join(testdataDir, "log1.log"),
	}

	acc := testutil.Accumulator{}
	acc.GatherError(fs.Gather)

	tags1 := map[string]string{
		"file": filepath.Join(testdataDir, "log1.log"),
		"use_match": "0",
	}
	require.True(t, acc.HasPoint("filestat", tags1, "size_bytes", int64(0)))
	require.True(t, acc.HasPoint("filestat", tags1, "exists", int64(1)))
	require.True(t, acc.HasInt64Field("filestat", "modification_time"))
}

func TestNoModificationTime(t *testing.T) {
	fs := NewFileStat()
	fs.Log = testutil.Logger{}
	fs.Files = []string{
		filepath.Join(testdataDir, "non_existent_file"),
	}

	acc := testutil.Accumulator{}
	acc.GatherError(fs.Gather)

	tags1 := map[string]string{
		"file": filepath.Join(testdataDir, "non_existent_file"),
		"use_match": "0",
	}
	require.True(t, acc.HasPoint("filestat", tags1, "exists", int64(0)))
	require.False(t, acc.HasInt64Field("filestat", "modification_time"))
}

func TestGetMd5(t *testing.T) {
	md5, err := getMd5(filepath.Join(testdataDir, "test.conf"))
	assert.NoError(t, err)
	assert.Equal(t, "5a7e9b77fa25e7bb411dbd17cf403c1f", md5)

	md5, err = getMd5("/tmp/foo/bar/fooooo")
	assert.Error(t, err)
}

func getTestdataDir() string {
	dir, err := os.Getwd()
	if err != nil {
		// if we cannot even establish the test directory, further progress is meaningless
		panic(err)
	}

	return filepath.Join(dir, "testdata")
}
