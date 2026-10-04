-- Bind each immutable side-effect row to one exact aggregate event, not merely an event ID.
ALTER TABLE keel_meta.order_events
    ADD CONSTRAINT order_events_effect_aggregate_identity_unique
    UNIQUE (tenant_id, event_id, order_id, aggregate_version),
    ADD CONSTRAINT order_events_effect_type_identity_unique
    UNIQUE (tenant_id, event_id, order_id, aggregate_version, event_type);

ALTER TABLE keel_meta.event_outbox
    ADD CONSTRAINT event_outbox_exact_event_fk
    FOREIGN KEY (tenant_id, event_id, aggregate_id, aggregate_version, event_type)
    REFERENCES keel_meta.order_events (tenant_id, event_id, order_id, aggregate_version, event_type);

ALTER TABLE keel_meta.state_updates
    ADD CONSTRAINT state_updates_exact_event_fk
    FOREIGN KEY (tenant_id, event_id, aggregate_id, aggregate_version)
    REFERENCES keel_meta.order_events (tenant_id, event_id, order_id, aggregate_version);
