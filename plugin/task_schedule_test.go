package plugin

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"
)

func validSchedule() TaskSchedule {
	return TaskSchedule{
		ID: "artifact.sync-all", Cron: "*/5 * * * *",
		Service: "latticenet.sub-store/artifacts", Method: "sync_all",
		Payload: json.RawMessage(`{"destination":"r2"}`),
	}
}

func TestTaskScheduleWireNames(t *testing.T) {
	raw, err := json.Marshal(validSchedule())
	if err != nil {
		t.Fatal(err)
	}
	want := `{"id":"artifact.sync-all","cron":"*/5 * * * *","service":"latticenet.sub-store/artifacts","method":"sync_all","payload":{"destination":"r2"}}`
	if string(raw) != want {
		t.Fatalf("task schedule encodes as\n %s\nwant %s", raw, want)
	}
	if CapabilityTaskSchedule != "task:schedule" || HostMethodTaskSchedule != "task.schedule" || HostMethodTaskUnschedule != "task.unschedule" {
		t.Fatal("task schedule names changed")
	}
}

func TestCronMinIntervalAtTheFiveMinuteEdge(t *testing.T) {
	cases := []struct {
		cron string
		want time.Duration
	}{
		{"*/5 * * * *", 5 * time.Minute},
		{"0-59/5 * * * *", 5 * time.Minute},
		{"*/4 * * * *", 4 * time.Minute},
		{"* * * * *", time.Minute},
		{"0,4 * * * *", 4 * time.Minute},
		{"0,5 * * * *", 5 * time.Minute},
		// 01:58 then 02:00: the gap crosses an hour boundary.
		{"0,58 1-2 * * *", 2 * time.Minute},
		// 23:58 then 00:00 the next day: the gap wraps the day.
		{"0,58 0,23 * * *", 2 * time.Minute},
		{"30 3 * * 1", 24 * time.Hour},
		{"0 */6 1-15 1,7 0-7", 6 * time.Hour},
	}
	for _, c := range cases {
		got, err := CronMinInterval(c.cron)
		if err != nil {
			t.Fatalf("%q: %v", c.cron, err)
		}
		if got != c.want {
			t.Fatalf("%q: min interval %s, want %s", c.cron, got, c.want)
		}
		s := validSchedule()
		s.Cron = c.cron
		if err := s.Validate(); (err == nil) != (c.want >= MinTaskScheduleInterval) {
			t.Fatalf("%q at %s: Validate() = %v", c.cron, c.want, err)
		}
	}
}

func TestCronDialectRefusesWhatItDoesNotDefine(t *testing.T) {
	for _, cron := range []string{
		"", "* * * *", "* * * * * *", "@hourly", "0 0 * JAN *", "0 0 * * MON", "0 0 ? * *",
		"0 0 L * *", "60 * * * *", "0 24 * * *", "0 0 0 * *", "0 0 32 * *", "0 0 * 13 *", "0 0 * * 8",
		"5-1 * * * *", "*/0 * * * *", "5/10 * * * *", "1,,2 * * * *", "-1 * * * *", "100 * * * *",
		strings.Repeat("0,", 64) + "0 * * * *",
	} {
		if _, err := CronMinInterval(cron); err == nil {
			t.Fatalf("cron %q accepted", cron)
		}
	}
}

func TestTaskScheduleFieldBounds(t *testing.T) {
	mutate := func(edit func(*TaskSchedule)) error {
		s := validSchedule()
		edit(&s)
		return s.Validate()
	}
	if err := mutate(func(s *TaskSchedule) { s.ID = strings.Repeat("a", MaxTaskScheduleIDBytes) }); err != nil {
		t.Fatalf("id at the bound refused: %v", err)
	}
	if err := mutate(func(s *TaskSchedule) { s.ID = strings.Repeat("a", MaxTaskScheduleIDBytes+1) }); err == nil {
		t.Fatal("id one byte over the bound accepted")
	}
	for _, id := range []string{"", "-x", "Upper", "has space", "a/b"} {
		if err := mutate(func(s *TaskSchedule) { s.ID = id }); err == nil {
			t.Fatalf("id %q accepted", id)
		}
	}
	payload := func(n int) json.RawMessage { return json.RawMessage(`"` + strings.Repeat("p", n-2) + `"`) }
	if err := mutate(func(s *TaskSchedule) { s.Payload = payload(MaxTaskSchedulePayloadBytes) }); err != nil {
		t.Fatalf("payload at the bound refused: %v", err)
	}
	if err := mutate(func(s *TaskSchedule) { s.Payload = payload(MaxTaskSchedulePayloadBytes + 1) }); err == nil {
		t.Fatal("payload one byte over the bound accepted")
	}
	if err := mutate(func(s *TaskSchedule) { s.Payload = json.RawMessage(`{"x":`) }); err == nil {
		t.Fatal("payload that is not JSON accepted")
	}
	if err := mutate(func(s *TaskSchedule) { s.Payload = nil }); err != nil {
		t.Fatalf("schedule without payload refused: %v", err)
	}
	for _, edit := range []func(*TaskSchedule){
		func(s *TaskSchedule) { s.Service = "" },
		func(s *TaskSchedule) { s.Method = "" },
		func(s *TaskSchedule) { s.Method = "sync all" },
		func(s *TaskSchedule) { s.Service = strings.Repeat("s", MaxTaskScheduleNameBytes+1) },
	} {
		if err := mutate(edit); err == nil {
			t.Fatal("invalid service or method accepted")
		}
	}
}

func TestTaskScheduleSetHoldsAtMostSixtyFour(t *testing.T) {
	set := make([]TaskSchedule, 0, MaxTaskSchedulesPerPlugin+1)
	for i := 0; i < MaxTaskSchedulesPerPlugin; i++ {
		s := validSchedule()
		s.ID = fmt.Sprintf("s-%02d", i)
		set = append(set, s)
	}
	if err := ValidateTaskSchedules(set); err != nil {
		t.Fatalf("%d schedules refused: %v", len(set), err)
	}
	extra := validSchedule()
	extra.ID = "s-64"
	if err := ValidateTaskSchedules(append(set, extra)); err == nil {
		t.Fatal("a 65th schedule accepted")
	}
	if err := ValidateTaskSchedules([]TaskSchedule{validSchedule(), validSchedule()}); err == nil {
		t.Fatal("two schedules with one id accepted")
	}
}
