package filestat

import (
	"errors"
	"crypto/md5"
	"hash/crc32"
	"fmt"
	"io"
	"os"
	"os/exec"
	"time"

	"github.com/influxdata/telegraf"
	"github.com/influxdata/telegraf/internal"
	"github.com/influxdata/telegraf/internal/globpath"
	"github.com/influxdata/telegraf/plugins/inputs"
	"github.com/kballard/go-shellquote"
)

const sampleConfig = `
  ## Files to gather stats about.
  ## These accept standard unix glob matching rules, but with the addition of
  ## ** as a "super asterisk". ie:
  ##   "/var/log/**.log"  -> recursively find all .log files in /var/log
  ##   "/var/log/*/*.log" -> find all .log files with a parent dir in /var/log
  ##   "/var/log/apache.log" -> just tail the apache log file
  ##
  ## See https://github.com/gobwas/glob for more examples
  ##
  files = ["/var/log/**.log"]

  ## If true, read the entire file and calculate an md5 checksum.
  md5 = false

  ## If true, will calculate the md5's crc checksum, to adapt prometheus value
  md5_crc = false

  use_match = true
  match_cmd = "wm-logfilter --last-minutes 1 --maxline 1 --match 'kernel|timeout|error'"
  timeout = "5s"
`

type FileStat struct {
	Md5   bool
	Md5Crc bool

	Log telegraf.Logger

	UseMatch bool
	UseSudo bool
	MatchCmd string
	Timeout internal.Duration

	Files []string

	// maps full file paths to globmatch obj
	globs map[string]*globpath.GlobPath

	// files that were missing - we only log the first time it's not found.
	missingFiles map[string]bool
	// files that had an error in Stat - we only log the first error.
	filesWithErrors map[string]bool
}

func NewFileStat() *FileStat {
	return &FileStat{
		globs:           make(map[string]*globpath.GlobPath),
		missingFiles:    make(map[string]bool),
		filesWithErrors: make(map[string]bool),
		UseMatch: false,
		Timeout: internal.Duration{Duration: time.Second * 5},
	}
}

func (*FileStat) Description() string {
	return "Read stats about given file(s)"
}

func (*FileStat) SampleConfig() string { return sampleConfig }

func (f *FileStat) PreGather() error {
	if f.UseMatch {
		if len(f.MatchCmd) == 0 {
			f.Log.Warn("does not set match_cmd")
			return errors.New("does not set match_cmd")
		} else {
			if len(f.MatchCmd) == 0 {
				f.UseMatch = false
				f.Log.Warn("match_cmd is empty, set use_match to false")
				return errors.New("match_cmd is empty")
			}
		}
	}

	return nil
}

func (f *FileStat) Gather(acc telegraf.Accumulator) error {
	var err error

	_ = f.PreGather()

	for _, filepath := range f.Files {
		// Get the compiled glob object for this filepath
		g, ok := f.globs[filepath]
		if !ok {
			if g, err = globpath.Compile(filepath); err != nil {
				acc.AddError(err)
				continue
			}
			f.globs[filepath] = g
		}

		var matchTagVal string = "0"
		if f.UseMatch {
			matchTagVal = "1"
		}

		files := g.Match()
		if len(files) == 0 {
			acc.AddFields("filestat",
				map[string]interface{}{
					"exists": int64(0),
				},
				map[string]string{
					"file": filepath,
					"use_match": matchTagVal,
				})
			continue
		}

		for _, fileName := range files {
			tags := map[string]string{
				"file": fileName,
				"use_match": matchTagVal,
			}
			fields := map[string]interface{}{
				"exists": int64(1),
			}
			fileInfo, err := os.Stat(fileName)
			if os.IsNotExist(err) {
				fields["exists"] = int64(0)
				acc.AddFields("filestat", fields, tags)
				if !f.missingFiles[fileName] {
					f.Log.Warnf("File %q not found", fileName)
					f.missingFiles[fileName] = true
				}
				continue
			}
			f.missingFiles[fileName] = false

			if fileInfo == nil {
				if !f.filesWithErrors[fileName] {
					f.filesWithErrors[fileName] = true
					f.Log.Errorf("Unable to get info for file %q: %v",
						fileName, err)
				}
			} else {
				f.filesWithErrors[fileName] = false
				fields["size_bytes"] = fileInfo.Size()
				fields["modification_time"] = fileInfo.ModTime().UnixNano()
			}

			if f.Md5 || f.Md5Crc {
				md5, err := getMd5(fileName)
				if err != nil {
					acc.AddError(err)
				} else {
					if f.Md5Crc {
						fields["md5_crc"] = int64(stringCrc(md5))
					} else {
						fields["md5_sum"] = md5
					}
				}
			}

			if f.UseMatch {
				isMatch, err := f.RunMatchCmd(fileName)

				fields["is_match"] = isMatch
				if err != nil {
					acc.AddError(err)
				}
			}

			acc.AddFields("filestat", fields, tags)
		}
	}

	return nil
}

// 0: no macth, 1: match, 2: error
func (f *FileStat) RunMatchCmd(file string) (int64, error) {
	if !f.UseMatch {
		return 0, errors.New("use_match is false")
	}

	var cmdline = f.MatchCmd + " " + file
	splitCmd, err := shellquote.Split(cmdline)
	if err != nil || len(splitCmd) == 0 {
		return 2, fmt.Errorf("exec: unable to parse command, %s", err)
	}

	cmd := exec.Command(splitCmd[0], splitCmd[1:]...)
	out, err := internal.CombinedOutputTimeout(cmd, f.Timeout.Duration)

	if err != nil {
		if exiterr, ok := err.(*exec.ExitError); ok {
			// get exit code, return 0 if is 1
			if exiterr.ExitCode() == 1 {
				return 0, nil
			}
		}
		return 2, err
	}

	if len(out) > 0 {
		return 1, nil
	} else {
		return 0, nil
	}
}

// calculate crc32 and return integer
func stringCrc(data string) uint32 {
	if len(data) == 0 {
		return 0
	}

	crc32q := crc32.MakeTable(0xD5828281)
	return crc32.Checksum([]byte(data), crc32q)
}

// Read given file and calculate an md5 hash.
func getMd5(file string) (string, error) {
	of, err := os.Open(file)
	if err != nil {
		return "", err
	}
	defer of.Close()

	hash := md5.New()
	_, err = io.Copy(hash, of)
	if err != nil {
		// fatal error
		return "", err
	}
	return fmt.Sprintf("%x", hash.Sum(nil)), nil
}

func init() {
	inputs.Add("filestat", func() telegraf.Input {
		return NewFileStat()
	})
}
