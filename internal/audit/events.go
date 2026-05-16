package audit

// Event constructors per audit action. Each one wires ECS event.*
// vocabulary correctly so SIEM dashboards can filter by category/type
// without bespoke parsing. References:
//   - event.category: https://www.elastic.co/guide/en/ecs/current/ecs-allowed-values-event-category.html
//   - event.type:     https://www.elastic.co/guide/en/ecs/current/ecs-allowed-values-event-type.html

// ----- server lifecycle ------------------------------------------------

func ServerStarted(listenAddr string, authEnabled bool) Event {
	mode := "no-auth"
	if authEnabled {
		mode = "basic-auth"
	}
	return Event{
		Event: EventCore{
			Kind:     "event",
			Category: []string{"configuration"},
			Type:     []string{"start"},
			Action:   "server.started",
			Outcome:  "success",
		},
		Message: "fipscan server started on " + listenAddr + " (" + mode + ")",
	}
}

func ServerStopped() Event {
	return Event{
		Event: EventCore{
			Kind:     "event",
			Category: []string{"configuration"},
			Type:     []string{"end"},
			Action:   "server.stopped",
			Outcome:  "success",
		},
		Message: "fipscan server stopped",
	}
}

// ----- authentication --------------------------------------------------

func LoginFailure(username, sourceIP, reason string) Event {
	return Event{
		Event: EventCore{
			Kind:     "event",
			Category: []string{"authentication"},
			Type:     []string{"start"},
			Action:   "auth.login_failure",
			Outcome:  "failure",
			Reason:   reason,
		},
		Source:  &NetSource{IP: sourceIP},
		User:    &User{Name: username},
		Message: "failed login attempt for user " + safeUser(username),
	}
}

// ----- target watchlist CRUD -------------------------------------------

func TargetAdded(targetID, targetType, targetValue, sourceIP, actor string) Event {
	return Event{
		Event: EventCore{
			Kind:     "event",
			Category: []string{"configuration"},
			Type:     []string{"creation"},
			Action:   "target.added",
			Outcome:  "success",
		},
		Source: &NetSource{IP: sourceIP},
		User:   user(actor),
		Fipscan: &Fipscan{
			Target: &Target{ID: targetID, Type: targetType, Value: targetValue},
		},
		Message: "added " + targetType + " target " + targetValue,
	}
}

func TargetDeleted(targetID, sourceIP, actor string) Event {
	return Event{
		Event: EventCore{
			Kind:     "event",
			Category: []string{"configuration"},
			Type:     []string{"deletion"},
			Action:   "target.deleted",
			Outcome:  "success",
		},
		Source: &NetSource{IP: sourceIP},
		User:   user(actor),
		Fipscan: &Fipscan{
			Target: &Target{ID: targetID},
		},
		Message: "deleted target " + targetID,
	}
}

func TargetScanRequested(targetID, sourceIP, actor string) Event {
	return Event{
		Event: EventCore{
			Kind:     "event",
			Category: []string{"process"},
			Type:     []string{"start"},
			Action:   "target.scan_requested",
			Outcome:  "success",
		},
		Source: &NetSource{IP: sourceIP},
		User:   user(actor),
		Fipscan: &Fipscan{
			Target: &Target{ID: targetID},
		},
		Message: "manual scan requested for " + targetID,
	}
}

// ----- scan lifecycle --------------------------------------------------

func ScanStarted(targetID, targetType, targetValue, scanID string) Event {
	return Event{
		Event: EventCore{
			Kind:     "event",
			Category: []string{"process"},
			Type:     []string{"start"},
			Action:   "scan.started",
			Outcome:  "unknown",
		},
		Fipscan: &Fipscan{
			Target: &Target{ID: targetID, Type: targetType, Value: targetValue},
			Scan:   &Scan{ID: scanID},
		},
		Message: "scan " + scanID + " started for " + targetValue,
	}
}

func ScanCompleted(targetID, targetType, targetValue, scanID string, durationMS int64, total, high, medium, low int) Event {
	return Event{
		Event: EventCore{
			Kind:     "event",
			Category: []string{"process"},
			Type:     []string{"end"},
			Action:   "scan.completed",
			Outcome:  "success",
		},
		Fipscan: &Fipscan{
			Target:   &Target{ID: targetID, Type: targetType, Value: targetValue},
			Scan:     &Scan{ID: scanID, DurationMS: durationMS},
			Findings: &Findings{Total: total, High: high, Medium: medium, Low: low},
		},
		Message: "scan " + scanID + " completed: " + itoa(total) + " findings",
	}
}

func ScanFailed(targetID, targetType, targetValue, scanID string, durationMS int64, err string) Event {
	return Event{
		Event: EventCore{
			Kind:     "event",
			Category: []string{"process"},
			Type:     []string{"end"},
			Action:   "scan.failed",
			Outcome:  "failure",
			Reason:   err,
		},
		Fipscan: &Fipscan{
			Target: &Target{ID: targetID, Type: targetType, Value: targetValue},
			Scan:   &Scan{ID: scanID, DurationMS: durationMS},
		},
		Message: "scan " + scanID + " failed: " + err,
	}
}

// ----- alert configuration + delivery ----------------------------------

func AlertConfigured(alertID, alertName, sourceIP, actor string) Event {
	return Event{
		Event: EventCore{
			Kind:     "event",
			Category: []string{"configuration"},
			Type:     []string{"creation"},
			Action:   "alert.configured",
			Outcome:  "success",
		},
		Source: &NetSource{IP: sourceIP},
		User:   user(actor),
		Fipscan: &Fipscan{
			Alert: &Alert{ID: alertID, Name: alertName},
		},
		Message: "alert destination added: " + alertName,
	}
}

func AlertUnconfigured(alertID, sourceIP, actor string) Event {
	return Event{
		Event: EventCore{
			Kind:     "event",
			Category: []string{"configuration"},
			Type:     []string{"deletion"},
			Action:   "alert.unconfigured",
			Outcome:  "success",
		},
		Source: &NetSource{IP: sourceIP},
		User:   user(actor),
		Fipscan: &Fipscan{
			Alert: &Alert{ID: alertID},
		},
		Message: "alert destination removed: " + alertID,
	}
}

func AlertDelivered(alertID, alertName, scanID string, findingsCount int) Event {
	return Event{
		Event: EventCore{
			Kind:     "event",
			Category: []string{"network"},
			Type:     []string{"info"},
			Action:   "alert.delivered",
			Outcome:  "success",
		},
		Fipscan: &Fipscan{
			Alert:    &Alert{ID: alertID, Name: alertName},
			Scan:     &Scan{ID: scanID},
			Findings: &Findings{Total: findingsCount},
		},
		Message: "alert delivered to " + alertName + " (" + itoa(findingsCount) + " findings)",
	}
}

func AlertDeliveryFailed(alertID, alertName, scanID, err string) Event {
	return Event{
		Event: EventCore{
			Kind:     "event",
			Category: []string{"network"},
			Type:     []string{"info"},
			Action:   "alert.delivery_failed",
			Outcome:  "failure",
			Reason:   err,
		},
		Fipscan: &Fipscan{
			Alert: &Alert{ID: alertID, Name: alertName},
			Scan:  &Scan{ID: scanID},
		},
		Message: "alert delivery to " + alertName + " failed: " + err,
	}
}

// ----- helpers ---------------------------------------------------------

func user(name string) *User {
	if name == "" {
		return nil
	}
	return &User{Name: name}
}

func safeUser(s string) string {
	if s == "" {
		return "(none)"
	}
	return s
}

// itoa avoids strconv import for a single use; tiny and obvious.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}
