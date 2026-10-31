package httpapi

import (
	"html/template"
	"io"
	"net/http"
	"strings"

	"github.com/sanskarpan/keel/internal/delivery/webhook"
)

// uiPage is the content-free view model for the read-only operator dashboard. It carries
// identities, counts and timestamps only; URLs, payloads, keys, secrets and receiver content
// never reach the template.
type uiPage struct {
	Runs       []webhook.ReconciliationRunSummary
	Candidates []webhook.Delivery
	Skipped    []webhook.ReplaySkip
}

var uiTemplate = template.Must(template.New("operator").Parse(`<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><title>Keel webhook operations</title></head>
<body>
<h1>Keel webhook operations (read-only)</h1>
<h2>Recent reconciliation runs</h2>
<table><thead><tr><th>Run</th><th>Requested by</th><th>Scanned</th><th>Gaps</th><th>Missing</th><th>Repaired</th><th>Skipped</th><th>Recorded</th></tr></thead>
<tbody>{{range .Runs}}<tr><td>{{.RunID}}</td><td>{{.RequestedBy}}</td><td>{{.EventsScanned}}</td><td>{{.GapEvents}}</td><td>{{.MissingDeliveries}}</td><td>{{.RepairedDeliveries}}</td><td>{{.SkippedIdentities}}</td><td>{{.CreatedAt.UTC.Format "2006-01-02 15:04:05Z"}}</td></tr>{{else}}<tr><td colspan="8">no runs recorded</td></tr>{{end}}</tbody>
</table>
<h2>Replay candidates</h2>
<table><thead><tr><th>Delivery</th><th>Event</th><th>Endpoint</th><th>Revision</th></tr></thead>
<tbody>{{range .Candidates}}<tr><td>{{.ID}}</td><td>{{.Identity.EventID}}</td><td>{{.Identity.EndpointID}}</td><td>{{.Identity.SubscriptionVersion}}</td></tr>{{else}}<tr><td colspan="4">no candidates</td></tr>{{end}}</tbody>
</table>
<h2>Skipped</h2>
<table><thead><tr><th>Delivery</th><th>Reason</th></tr></thead>
<tbody>{{range .Skipped}}<tr><td>{{.DeliveryID}}</td><td>{{.Reason}}</td></tr>{{else}}<tr><td colspan="2">none skipped</td></tr>{{end}}</tbody>
</table>
<p>Mutations stay on the JSON API. This page never shows URLs, payloads, or signing material.</p>
</body>
</html>`))

// serveUI renders the read-only dashboard for an authorized bearer principal. It uses the
// request's Authorization header like every other route, so browsers need header injection;
// tokens never appear in URLs.
func (h *Handler) serveUI(w http.ResponseWriter, r *http.Request) {
	principal, ok := h.principal(w, r)
	if !ok {
		return
	}
	if !h.authz.CanReplayWebhooks(r.Context(), principal) {
		writeProblem(w, http.StatusForbidden, "forbidden")
		return
	}
	records, err := h.repo.ReplayCandidates(r.Context(), principal.TenantID, defaultCandidateLimit)
	if err != nil {
		writeProblem(w, http.StatusInternalServerError, "request_failed")
		return
	}
	candidates := make([]webhook.ReplayCandidate, 0, len(records))
	for _, record := range records {
		candidates = append(candidates, webhook.ReplayCandidate{
			Delivery: record.Delivery,
			State:    record.State,
			Attempts: record.Attempts,
			Replayed: record.Replayed,
			Endpoint: webhook.EndpointEligibility{
				Status:              record.EndpointStatus,
				SubscriptionVersion: record.Delivery.Identity.SubscriptionVersion,
				SignatureKeyReady: record.EndpointStatus == webhook.EndpointActive &&
					record.KeyID != "" && h.keyReady(record.KeyID),
			},
		})
	}
	selection, err := webhook.SelectReplay(candidates, defaultCandidateLimit)
	if err != nil {
		writeProblem(w, http.StatusInternalServerError, "request_failed")
		return
	}
	summaries, err := h.repo.ReconciliationRuns(r.Context(), principal.TenantID, defaultRunLimit)
	if err != nil {
		writeProblem(w, http.StatusInternalServerError, "request_failed")
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	var rendered strings.Builder
	if err := uiTemplate.Execute(&rendered, uiPage{
		Runs:       summaries,
		Candidates: selection.Deliveries,
		Skipped:    selection.Skipped,
	}); err != nil {
		writeProblem(w, http.StatusInternalServerError, "request_failed")
		return
	}
	_, _ = io.WriteString(w, rendered.String())
}
