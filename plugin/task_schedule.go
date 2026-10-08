package plugin

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Host calls that schedule a plugin's own methods (design 28). Both need
// CapabilityTaskSchedule. task.schedule takes a TaskSchedule and replaces
// any schedule with the same id; task.unschedule takes {"id": "<id>"}. The
// server's task queue runs each schedule, never two runs of one id at once.
const (
	HostMethodTaskSchedule   = "task.schedule"
	HostMethodTaskUnschedule = "task.unschedule"
)

// Bounds of task schedules.
const (
	// MaxTaskSchedulesPerPlugin is how many schedules one plugin may hold.
	MaxTaskSchedulesPerPlugin = 64
	// MinTaskScheduleInterval is the shortest gap a schedule may leave
	// between two runs.
	MinTaskScheduleInterval = 5 * time.Minute
	// MaxTaskScheduleIDBytes bounds a schedule id.
	MaxTaskScheduleIDBytes = 64
	// MaxTaskScheduleCronBytes bounds a cron expression.
	MaxTaskScheduleCronBytes = 128
	// MaxTaskScheduleNameBytes bounds the service and method names.
	MaxTaskScheduleNameBytes = 128
	// MaxTaskSchedulePayloadBytes bounds the payload a schedule stores.
	MaxTaskSchedulePayloadBytes = 64 << 10
)

// TaskSchedule asks the server to call one of the plugin's own methods on a
// cron schedule, with a fixed payload, as the plugin's own principal.
type TaskSchedule struct {
	// ID names the schedule within the plugin: lowercase letters, digits,
	// '.', '_' and '-', starting with a letter or digit.
	ID string `json:"id"`
	// Cron is a five-field expression (minute, hour, day of month, month,
	// day of week) in the server's clock. Each field is "*", "*/n", "a",
	// "a-b", "a-b/n" or a comma list of those, numbers only; day of week is
	// 0 to 7 with 0 and 7 both Sunday. Names, "?", "L", "W", "#" and "@"
	// macros are refused. Two runs may never be closer than
	// MinTaskScheduleInterval.
	Cron string `json:"cron"`
	// Service is the interface the call goes to, as in a runtime call
	// payload. The server admits only an interface the plugin itself
	// declares.
	Service string `json:"service"`
	// Method is the method called on Service.
	Method string `json:"method"`
	// Payload is passed to the method on every run.
	Payload json.RawMessage `json:"payload,omitempty"`
}

var taskScheduleID = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]*$`)

// Validate checks a schedule's id, names, payload and cron expression,
// including the minimum interval.
func (s TaskSchedule) Validate() error {
	if len(s.ID) > MaxTaskScheduleIDBytes || !taskScheduleID.MatchString(s.ID) {
		return fmt.Errorf("task schedule id %q is invalid", s.ID)
	}
	for name, value := range map[string]string{"service": s.Service, "method": s.Method} {
		if value == "" || len(value) > MaxTaskScheduleNameBytes || strings.ContainsFunc(value, func(r rune) bool { return r <= ' ' || r == 0x7f }) {
			return fmt.Errorf("task schedule %s %q is invalid", name, value)
		}
	}
	if len(s.Payload) > MaxTaskSchedulePayloadBytes {
		return fmt.Errorf("task schedule payload exceeds %d bytes", MaxTaskSchedulePayloadBytes)
	}
	if len(s.Payload) > 0 && !json.Valid(s.Payload) {
		return errors.New("task schedule payload is not JSON")
	}
	interval, err := CronMinInterval(s.Cron)
	if err != nil {
		return err
	}
	if interval < MinTaskScheduleInterval {
		return fmt.Errorf("task schedule %q may run %s apart, under the %s minimum", s.ID, interval, MinTaskScheduleInterval)
	}
	return nil
}

// ValidateTaskSchedules checks the whole set one plugin holds: each schedule,
// unique ids, and at most MaxTaskSchedulesPerPlugin.
func ValidateTaskSchedules(schedules []TaskSchedule) error {
	if len(schedules) > MaxTaskSchedulesPerPlugin {
		return fmt.Errorf("a plugin may hold at most %d task schedules", MaxTaskSchedulesPerPlugin)
	}
	seen := make(map[string]struct{}, len(schedules))
	for _, s := range schedules {
		if err := s.Validate(); err != nil {
			return err
		}
		if _, dup := seen[s.ID]; dup {
			return fmt.Errorf("task schedule id %q is used twice", s.ID)
		}
		seen[s.ID] = struct{}{}
	}
	return nil
}

// CronMinInterval parses a five-field cron expression in the dialect
// TaskSchedule.Cron describes and returns the shortest gap it can leave
// between two runs. The gap is computed from the minute and hour fields
// over a day, counting the wrap from the last run of one day to the first of
// the next, so a restriction on days can only make the real gap longer.
func CronMinInterval(expr string) (time.Duration, error) {
	if len(expr) > MaxTaskScheduleCronBytes {
		return 0, fmt.Errorf("cron expression exceeds %d bytes", MaxTaskScheduleCronBytes)
	}
	fields := strings.Fields(expr)
	if len(fields) != 5 {
		return 0, fmt.Errorf("cron expression %q needs five fields", expr)
	}
	bounds := [5][2]int{{0, 59}, {0, 23}, {1, 31}, {1, 12}, {0, 7}}
	sets := make([][]int, 5)
	for i, field := range fields {
		set, err := parseCronField(field, bounds[i][0], bounds[i][1])
		if err != nil {
			return 0, fmt.Errorf("cron expression %q field %d: %w", expr, i+1, err)
		}
		sets[i] = set
	}
	var runs []int
	for _, hour := range sets[1] {
		for _, minute := range sets[0] {
			runs = append(runs, hour*60+minute)
		}
	}
	sort.Ints(runs)
	gap := runs[0] + 24*60 - runs[len(runs)-1]
	for i := 1; i < len(runs); i++ {
		gap = min(gap, runs[i]-runs[i-1])
	}
	return time.Duration(gap) * time.Minute, nil
}

// parseCronField returns the sorted, distinct values one field selects.
func parseCronField(field string, lo, hi int) ([]int, error) {
	selected := make(map[int]struct{})
	for _, item := range strings.Split(field, ",") {
		rangePart, stepPart, hasStep := strings.Cut(item, "/")
		step := 1
		if hasStep {
			n, err := cronNumber(stepPart)
			if err != nil || n < 1 {
				return nil, fmt.Errorf("invalid step in %q", item)
			}
			step = n
		}
		start, end := lo, hi
		switch {
		case rangePart == "*":
		case strings.Contains(rangePart, "-"):
			a, b, _ := strings.Cut(rangePart, "-")
			var errA, errB error
			start, errA = cronNumber(a)
			end, errB = cronNumber(b)
			if errA != nil || errB != nil || start > end {
				return nil, fmt.Errorf("invalid range %q", item)
			}
		default:
			if hasStep {
				return nil, fmt.Errorf("a step needs * or a range in %q", item)
			}
			n, err := cronNumber(rangePart)
			if err != nil {
				return nil, fmt.Errorf("invalid value %q", item)
			}
			start, end = n, n
		}
		if start < lo || end > hi {
			return nil, fmt.Errorf("%q is outside %d to %d", item, lo, hi)
		}
		for v := start; v <= end; v += step {
			selected[v] = struct{}{}
		}
	}
	out := make([]int, 0, len(selected))
	for v := range selected {
		out = append(out, v)
	}
	sort.Ints(out)
	return out, nil
}

// cronNumber parses one to two decimal digits, nothing else.
func cronNumber(s string) (int, error) {
	if len(s) == 0 || len(s) > 2 || strings.TrimLeft(s, "0123456789") != "" {
		return 0, errors.New("not a number")
	}
	return strconv.Atoi(s)
}
