package telegraf

import (
	"time"
	"github.com/beevik/ntp"
)

var TimeChangeInfo = TimeChange{ start: time.Now() }

type TimeChange struct {
	start   time.Time
	Offset  time.Duration
	Inited  bool
}

func (t *TimeChange) TimeDiff() time.Duration {
	curtime := time.Now()
	return curtime.Sub(t.start)
}

func (t *TimeChange) TimeAdjust() time.Time {
	diff := t.TimeDiff()
	return t.start.Add(t.Offset).Add(diff).Truncate(time.Second)
}

func (t *TimeChange) InitTime(server string) error {
	options := ntp.QueryOptions{Timeout: 3 * time.Second}
	response, err := ntp.QueryWithOptions(server, options)

	if err == nil {
		t.Offset = response.ClockOffset
		t.Inited = true
	} else {
		return err
	}

	return nil
}
