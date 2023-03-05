package megacli

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/influxdata/telegraf"
	"github.com/influxdata/telegraf/config"
	"github.com/influxdata/telegraf/internal"
	"github.com/influxdata/telegraf/plugins/inputs"
)

const (
	BYTE = 1 << (10 * iota)
	KILOBYTE
	MEGABYTE
	GIGABYTE
	TERABYTE
	PETABYTE
	EXABYTE
)

var invalidByteQuantityError = errors.New("byte quantity must be a positive integer with a unit of measurement like M, MB, MiB, G, GiB, or GB")

type Megacli struct {
	PathMegacli      string           `toml:"path_megacli"`
	GatherType       []string         `toml:"gather_type"`
	UseSudo          bool             `toml:"use_sudo"`
	Timeout          config.Duration  `toml:"timeout"`
	Log              telegraf.Logger  `toml:"-"`
}

func (*Megacli) Description() string {
	return "Get standard MegaCli metrics, requires MegaCli executable."
}

func (*Megacli) SampleConfig() string {
	return `
  ## Optionally specify the path to the megacli executable
  # path_megacli = "/usr/bin/MegaCli"

  ## Gather info of the following type:
  ## raid, disk, bbu
  ## default is gather all of the three type
  # gother_type = ["raid", "disk", "bbu"]

  ## On most platforms used cli utilities requires root access.
  ## Setting 'use_sudo' to true will make use of sudo to run MegaCli.
  ## Sudo must be configured to allow the telegraf user to run MegaCli
  ## without a password.
  # use_sudo = false

  ## Timeout for the cli command to complete.
  # timeout = "3s"
  `
}

func fileExists(file string) bool {
	info, err := os.Stat(file)

	if os.IsNotExist(err) {
		return false
	}
	// maybe permission err
	if err != nil {
		return false
	}
	return !info.IsDir()
}

func (m *Megacli) PreGather() error {
	var err error

	if len(m.PathMegacli) > 0 {
		if !fileExists(m.PathMegacli) {
			m.Log.Warn("MegaCli is not exist or permission deny!")
		}
	} else {
		m.PathMegacli, err = exec.LookPath("MegaCli")
		if err != nil {
			m.PathMegacli = ""
			m.Log.Warn("MegaCli not found: verify that MegaCli is installed and that MegaCli is in your PATH")
		}
	}

	for _, tval := range m.GatherType {
		if tval != "raid" && tval != "disk" && tval != "bbu" {
			m.GatherType = nil
			m.Log.Errorf(fmt.Sprintf("gother_type: unknown type %s, must be raid, disk or bbu", tval))
		}
	}
	if len(m.GatherType) == 0 {
		m.GatherType = []string{"raid", "disk", "bbu"}
	}


	ver := m.getMegacliVersion()
	if ver == float64(0.0) {
			m.Log.Error("MegaCli: can not get version, may be not add sudo privileges!")
	} else {
		if ver < 8.0 {
			m.Log.Warnf("MegaCli [Ver %.2f] is too old, maybe cause performance issue when the system is busy!", ver)
		}
	}

	if m.Timeout == 0 {
		m.Timeout = config.Duration(time.Second * 3)
	}
	return nil
}

// Wrap with sudo
var runCmd = func(timeout config.Duration, sudo bool, command string, args ...string) ([]byte, error) {
	cmd := exec.Command(command, args...)
	if sudo {
		cmd = exec.Command("sudo", append([]string{"-n", command}, args...)...)
	}
	return internal.CombinedOutputTimeout(cmd, time.Duration(timeout))
}

// parse line and return the group values
func getSubstr(regEx, line string) (subsMap map[string]string) {
	var compRegEx = regexp.MustCompile(regEx)
	match := compRegEx.FindStringSubmatch(line)

	subsMap = make(map[string]string)
	for i, name := range compRegEx.SubexpNames() {
		if i > 0 && i <= len(match) {
			subsMap[name] = match[i]
		}
	}
	return subsMap
}

func (m *Megacli) getMegacliVersion() (float64) {
	out, err := runCmd(m.Timeout, m.UseSudo, m.PathMegacli, "-v", "-Nolog")
	if err != nil {
		return float64(0.0)
	}
	vp := getSubstr(`Tool\s+Ver\s+(?P<ver>\d\.\d{1,2})\..+`, string(out))
	if fval, err := strconv.ParseFloat(vp["ver"], 64); err == nil {
		return fval
	}
	return float64(0.0)
}

func (m *Megacli) Gather(acc telegraf.Accumulator) error {
	var err error

	_ = m.PreGather()

	if len(m.GatherType) == 0 {
		return nil
	}

	for _, gatherType := range m.GatherType {
		if gatherType == "raid" {
			out, err := runCmd(m.Timeout, m.UseSudo, m.PathMegacli, "-LDInfo", "-LALL", "-aAll", "-Nolog")
			if err == nil {
				err = m.gatherRaidStatus(string(out), acc)
			}
		}
		if gatherType == "disk" {
			out, err := runCmd(m.Timeout, m.UseSudo, m.PathMegacli, "-PDList", "-aALL", "-Nolog")
			if err == nil {
				err = m.gatherDiskStatus(string(out), acc)
			}
		}
		if gatherType == "bbu" {
			out, err := runCmd(m.Timeout, m.UseSudo, m.PathMegacli, "-AdpBbuCmd", "-GetBbuStatus", "-aALL", "-Nolog")
			if err == nil {
				err = m.gatherBbuStatus(string(out), acc)
			}
		}
		if err != nil {
			m.Log.Errorf("gather error for %s - %v", gatherType, err)
		}
	}

	return nil
}

func (m *Megacli) gatherRaidStatus(out string, acc telegraf.Accumulator) error {
	if !strings.Contains(out, "Virtual Drive Information") {
		return errors.New("unexpected output from Megacli - raid!")
	}

	var mark int64 = 0
	if strings.Contains(out, "Number of Dedicated Hot Spares") {
		mark = 1
	}


	tags := map[string]string{}
	fields := map[string]interface{}{}
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	var adapter_no string

	for _, line := range lines {
		if len(line) == 0 {
			continue
		}
		// global vars for multiple Vritual Drive
		if strings.HasPrefix(line, "Adapter") {
			ap := getSubstr(`Adapter\s+(?P<num>\d+)\s+--`, line)
			if len(ap) == 0 {
				return errors.New("can not match Adapter number")
			}
			adapter_no = ap["num"]
		}
		stats := strings.SplitN(line, ":", 2)
		if len(stats) < 2 {
			continue
		}
		if strings.HasPrefix(stats[0], "Virtual Drive") {
			vp := getSubstr(`\s+(?P<num>\d+)\s`, stats[1])
			if len(vp) == 1 {
				tags["virtual_drive"] = vp["num"]
			}
			fields["hotspares_num"] = int64(0) // initial hotspares at the begin Virtual Drive
		}
		if strings.HasPrefix(stats[0], "RAID Level") {
			lp := getSubstr(`Primary-(?P<primary>\d+),\sSecondary-(?P<secondary>\d+),\s+RAID Level Qualifier-(?P<qualifier>\d+)`, stats[1])
			if len(lp) == 3 {
				tags["level_primary"] = lp["primary"]
				tags["level_secondary"] = lp["secondary"]
				tags["level_qualifier"] = lp["qualifier"]
			}
		}
		if strings.HasPrefix(stats[0], "Size") {
			fields["size"], _ = toBytes(stats[1])
		}
		if strings.HasPrefix(stats[0], "Sector Size") {
			fields["sector_size"] = int(0)
			if sval, err := strconv.ParseInt(strings.TrimSpace(stats[1]), 10, 64); err == nil {
				fields["sector_size"] = sval
			}
		}
		if strings.HasPrefix(stats[0], "Parity Size") {
			fields["parity_size"], _ = toBytes(stats[1])
		}
		if strings.HasPrefix(stats[0], "State") {
			var stateVal int64 = 0
			switch strings.TrimSpace(stats[1]) {
			case "Optimal":
				stateVal = 1
			case "Degraded":
				stateVal = 2
			case "Offline":
				stateVal = 3
			}
			fields["state"] = stateVal
		}
		if strings.HasPrefix(stats[0], "Strip Size") {
			fields["strip_size"], _ = toBytes(stats[1])
		}
		if strings.HasPrefix(stats[0], "Number Of Drives") {
			fields["drives_cnt"] = int64(0)
			if nval, err := strconv.ParseInt(strings.TrimSpace(stats[1]), 10, 64); err == nil {
				fields["drives_cnt"] = nval
			}
		}
		if strings.HasPrefix(stats[0], "Current Cache Policy") {
			items := strings.Split(strings.TrimSpace(stats[1]), ",")
			var itemVal int64
			if len(items) > 0 {
				if strings.EqualFold(items[0], "WriteBack") {
					itemVal = 1
				}
				if strings.EqualFold(items[0], "WriteThrough") {
					itemVal = 2
				}
			}
			fields["cache_policy"] = itemVal
		}
		if strings.HasPrefix(stats[0], "Bad Blocks Exist") {
			var blockExist int64
			if strings.EqualFold(strings.TrimSpace(stats[1]), "No") {
				blockExist = 0
			} else {
				blockExist = 1
			}
			fields["exist_bad_blocks"] = blockExist
			tags["adapter"] = adapter_no
			if mark == 0 {
				acc.AddFields("megacli_raid", fields, tags)
				tags = map[string]string{}
				fields = map[string]interface{}{}
			}

		}
		if strings.HasPrefix(stats[0], "Number of Dedicated Hot Spares") {
			if hval, err := strconv.ParseInt(strings.TrimSpace(stats[1]), 10, 64); err == nil {
				fields["hotspares_num"] = hval
			}

			if mark == 1 {
				acc.AddFields("megacli_raid", fields, tags)
				tags = map[string]string{}
				fields = map[string]interface{}{}
			}

		}
	}
	return nil
}

func (m *Megacli) gatherDiskStatus(out string, acc telegraf.Accumulator) error {
	if !strings.Contains(out, "Enclosure Device ID") {
		return errors.New("unexpected output from Megacli - disk")
	}

	tags := map[string]string{}
	fields := map[string]interface{}{}
	lines := strings.Split(strings.TrimSpace(out), "\n")
	var adapter_no string

	for _, line := range lines {
		if len(line) == 0 {
			continue
		}

		// global vars for multiple Vritual Drive
		if strings.HasPrefix(line, "Adapter #") {
			ap := getSubstr(`Adapter\s+#(?P<num>\d+)`, line)
			if len(ap) == 0 {
				return errors.New("can not match Adapter number")
			}
			adapter_no = ap["num"]
		}

		stats := strings.SplitN(strings.TrimSpace(line), ":", 2)
		if len(stats) < 2 {
			continue
		}

		if strings.HasPrefix(stats[0], "Enclosure Device ID") {
			tags["en_deviceid"] = strings.TrimSpace(stats[1])
		}
		if strings.HasPrefix(stats[0], "Enclosure position") {
			tags["en_position"] = strings.TrimSpace(stats[1])
		}
		if strings.HasPrefix(stats[0], "Slot Number") {
			tags["slot"] = strings.TrimSpace(stats[1])
		}
		if strings.HasPrefix(stats[0], "Media Error Count") {
			fields["error_media_cnt"] = int64(0)
			if mval, err := strconv.ParseInt(strings.TrimSpace(stats[1]), 10, 64); err == nil {
				fields["error_media_cnt"] = mval
			}
		}
		if strings.HasPrefix(stats[0], "Other Error Count") {
			fields["error_other_cnt"] = int64(0)
			if oval, err := strconv.ParseInt(strings.TrimSpace(stats[1]), 10, 64); err == nil {
				fields["error_other_cnt"] = oval
			}
		}
		if strings.HasPrefix(stats[0], "Predictive Failure Count") {
			fields["error_prefailure_cnt"] = int64(0)
			if pval, err := strconv.ParseInt(strings.TrimSpace(stats[1]), 10, 64); err == nil {
				fields["error_prefailure_cnt"] = pval
			}
		}
		if strings.HasPrefix(stats[0], "Last Predictive Failure Event Seq Number") {
			fields["last_prefailure_seq"] = int(64)
			if lpval, err := strconv.ParseInt(strings.TrimSpace(stats[1]), 10, 64); err == nil {
				fields["last_prefailure_seq"] = lpval
			}
		}
		if strings.HasPrefix(stats[0], "PD Type") {
			tags["type"] = strings.TrimSpace(stats[1])
		}
		if strings.HasPrefix(stats[0], "Raw Size") {
			rp := getSubstr(`(?P<size>\d+\.\d+)\s+GB`, stats[1])
			fields["size_gb"] = float64(0.0)
			if len(rp) > 0 {
				if sgb, err := strconv.ParseFloat(rp["size"], 64); err == nil {
					fields["size_gb"] = sgb
				}
			} else {
				fields["size_gb"] = int64(0)
			}
		}
		if strings.HasPrefix(stats[0], "Firmware state") {
			sp := getSubstr(`(?P<state>\w+?)(?:,\s+|$)`, stats[1])
			var stateVal int64 = 9
			if len(sp) > 0 {
				switch sp["state"] {
				case "Failed":
					stateVal = -1
				case "Unconfigured":
					stateVal = 0
				case "Online":
					stateVal = 1
				case "Rebuild":
					stateVal = 2
				case "Hotspare":
					stateVal = 3
				}
			}
			fields["state"] = stateVal
		}
		if strings.HasPrefix(stats[0], "Locked") {
			var lval int64
			if strings.EqualFold(strings.TrimSpace(stats[1]), "Unlocked") {
				lval = 0
			} else {
				lval = 1
			}
			fields["islocked"] = lval
		}
		if strings.HasPrefix(stats[0], "Port status") {
			var lval int64
			if strings.EqualFold(strings.TrimSpace(stats[1]), "Active") {
				lval = 1
			}
			fields["port_status"] = lval
		}
		if strings.HasPrefix(stats[0], "Drive has flagged") {
			// end of current disk
			tags["adapter"] = adapter_no
			acc.AddFields("megacli_disk", fields, tags)
			tags = map[string]string{}
			fields = map[string]interface{}{}
		}
	}
	return nil
}

func (m *Megacli) gatherBbuStatus(out string, acc telegraf.Accumulator) error {
	if !strings.Contains(out, "BBU status for Adapter") {
		return errors.New("unexpected output from Megacli - bbu")
	}

	tags := map[string]string{}
	fields := map[string]interface{}{}
	lines := strings.Split(strings.TrimSpace(out), "\n")
	var adapter_no string

	for _, line := range lines {
		if len(line) == 0 {
			continue
		}
		stats := strings.SplitN(strings.TrimSpace(line), ":", 2)
		if len(stats) < 2 {
			continue
		}

		// global vars, maybe multiple Adapter
		if strings.HasPrefix(stats[0], "BBU status for Adapter") {
			adapter_no = strings.TrimSpace(stats[1])
		}
		if strings.HasPrefix(stats[0], "BatteryType") {
			tags["type"] = strings.TrimSpace(stats[1])
		}
		if strings.HasPrefix(stats[0], "Battery State") {
			var stateVal int64 = 0
			if strings.EqualFold(strings.TrimSpace(stats[1]), "Optimal") {
				stateVal = 1
			}
			fields["state"] = stateVal
		}
		if strings.HasPrefix(stats[0], "Relative State of Charge") {
			fields["charge_relative"] = int64(0)
			if cval, err := strconv.ParseInt(strings.TrimSpace(strings.TrimSuffix(stats[1], "%")), 10, 64); err == nil {
				fields["charge_relative"] = cval
			}
		}
		if strings.HasPrefix(stats[0], "Charger Status") {
			if strings.EqualFold(strings.TrimSpace(stats[1]), "Complete") {
				fields["charge_status"] = int64(1)
			} else {
				fields["charge_status"] = int64(0)
			}
		}
		if strings.HasPrefix(stats[0], "isSOHGood") {
			if strings.EqualFold(strings.TrimSpace(stats[1]), "Yes") {
				fields["issohgood"] = int64(1)
			} else {
				fields["issohgood"] = int64(0)
			}
			tags["adapter"] = adapter_no
			acc.AddFields("megacli_bbu", fields, tags)
			tags = map[string]string{}
			fields = map[string]interface{}{}
		}
	}
	return nil
}

// toBytes parses a string formatted by ByteSize as bytes. Note binary-prefixed and SI prefixed units both mean a base-2 units
// KB = K = KiB	= 1024
// MB = M = MiB = 1024 * K
// GB = G = GiB = 1024 * M
// TB = T = TiB = 1024 * G
// PB = P = PiB = 1024 * T
// EB = E = EiB = 1024 * P
func toBytes(s string) (uint64, error) {
	s = strings.TrimSpace(s)
	s = strings.ToUpper(s)
	s = strings.ReplaceAll(s, " ", "") // remove middle space

	i := strings.IndexFunc(s, unicode.IsLetter)

	if i == -1 {
		return 0, invalidByteQuantityError
	}

	bytesString, multiple := s[:i], s[i:]
	bytes, err := strconv.ParseFloat(bytesString, 64)
	if err != nil || bytes < 0 {
		return 0, invalidByteQuantityError
	}

	switch multiple {
	case "E", "EB", "EIB":
		return uint64(bytes * EXABYTE), nil
	case "P", "PB", "PIB":
		return uint64(bytes * PETABYTE), nil
	case "T", "TB", "TIB":
		return uint64(bytes * TERABYTE), nil
	case "G", "GB", "GIB":
		return uint64(bytes * GIGABYTE), nil
	case "M", "MB", "MIB":
		return uint64(bytes * MEGABYTE), nil
	case "K", "KB", "KIB":
		return uint64(bytes * KILOBYTE), nil
	case "B":
		return uint64(bytes), nil
	default:
		return 0, invalidByteQuantityError
	}
}



func init() {
	inputs.Add("megacli", func() telegraf.Input {
		return &Megacli{}
	})
}
