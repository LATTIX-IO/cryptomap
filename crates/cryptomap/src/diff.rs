//! Conservative inventory change tracking with per-evidence source confirmation.
use crate::{ChangeSet, CoverageState, Evidence, EvidenceId, InventorySnapshot};
use std::collections::{BTreeMap, BTreeSet};

type SourceKey = (u8, String, String);

fn successful(state: CoverageState) -> bool {
    matches!(
        state,
        CoverageState::InspectedObserved | CoverageState::InspectedNoObservation
    )
}

fn coverage(snapshot: &InventorySnapshot) -> BTreeMap<SourceKey, CoverageState> {
    let mut states = BTreeMap::new();
    for (source, state) in &snapshot.coverage {
        states.insert((0, String::new(), source.clone()), *state);
    }
    for record in &snapshot.coverage_records {
        if let Some(run) = snapshot.runs.get(&record.run) {
            let key = (1, run.scope.as_str().to_owned(), record.source_item.clone());
            states
                .entry(key)
                .and_modify(|state| {
                    // A failed or partial attempt is not upgraded to confirmed coverage
                    // by another independent attempt without explicit reconciliation.
                    if *state != record.state {
                        *state = CoverageState::Partial;
                    }
                })
                .or_insert(record.state);
        }
    }
    states
}
fn all_sources_complete(
    old: &InventorySnapshot,
    newer: &InventorySnapshot,
    old_coverage: &BTreeMap<SourceKey, CoverageState>,
    new_coverage: &BTreeMap<SourceKey, CoverageState>,
) -> bool {
    !old_coverage.is_empty()
        && old_coverage
            .keys()
            .all(|key| new_coverage.get(key).is_some_and(|s| successful(*s)))
        && newer
            .runs
            .values()
            .all(|run| matches!(run.completeness, crate::RunCompleteness::Complete))
        && new_coverage.values().all(|state| successful(*state))
        && (!old.assets.is_empty() || !old.observations.is_empty() || !old.coverage.is_empty())
}
fn rechecked(
    old: &InventorySnapshot,
    observed: &Evidence,
    new_coverage: &BTreeMap<SourceKey, CoverageState>,
) -> bool {
    let key = (0, String::new(), observed.source.clone());
    if new_coverage.get(&key).is_some_and(|s| successful(*s)) {
        return true;
    }
    let Some(run) = old.runs.get(&observed.run) else {
        return false;
    };
    let scoped = (1, run.scope.as_str().to_owned(), observed.source.clone());
    new_coverage.get(&scoped).is_some_and(|s| successful(*s))
}
fn split_removed<T: Ord + Clone>(
    old: &BTreeSet<T>,
    newer: &BTreeSet<T>,
    mut proven: impl FnMut(&T) -> bool,
) -> (BTreeSet<T>, BTreeSet<T>) {
    let mut removed = BTreeSet::new();
    let mut tentative = BTreeSet::new();
    for id in old.difference(newer) {
        if proven(id) {
            removed.insert(id.clone());
        } else {
            tentative.insert(id.clone());
        }
    }
    (removed, tentative)
}
fn evidence_proven(
    old: &InventorySnapshot,
    id: &EvidenceId,
    next: &BTreeMap<SourceKey, CoverageState>,
    global: bool,
) -> bool {
    old.evidence
        .get(id)
        .map_or(global, |e| rechecked(old, e, next))
}

impl InventorySnapshot {
    /// Compare two immutable inventories, confirming removals only when all
    /// evidence sources for each removed item were explicitly re-inspected.
    pub fn diff(&self, newer: &Self) -> ChangeSet {
        let old_cov = coverage(self);
        let new_cov = coverage(newer);
        let global = all_sources_complete(self, newer, &old_cov, &new_cov);
        let old_assets: BTreeSet<_> = self.assets.keys().cloned().collect();
        let new_assets: BTreeSet<_> = newer.assets.keys().cloned().collect();
        let old_obs: BTreeSet<_> = self.observations.keys().cloned().collect();
        let new_obs: BTreeSet<_> = newer.observations.keys().cloned().collect();
        let old_ev: BTreeSet<_> = self.evidence.keys().cloned().collect();
        let new_ev: BTreeSet<_> = newer.evidence.keys().cloned().collect();
        let old_rel: BTreeSet<_> = self.relationships.keys().cloned().collect();
        let new_rel: BTreeSet<_> = newer.relationships.keys().cloned().collect();
        let old_conf: BTreeSet<_> = self.conflicts.keys().cloned().collect();
        let new_conf: BTreeSet<_> = newer.conflicts.keys().cloned().collect();

        let (removed, tentative_removed) = split_removed(&old_assets, &new_assets, |asset| {
            let evidence: Vec<_> = self
                .observations
                .values()
                .filter(|o| &o.asset == asset)
                .map(|o| &o.evidence)
                .collect();
            if evidence.is_empty() {
                global
            } else {
                evidence
                    .into_iter()
                    .all(|id| evidence_proven(self, id, &new_cov, global))
            }
        });
        let (observations_removed, observations_tentative_removed) =
            split_removed(&old_obs, &new_obs, |id| {
                self.observations
                    .get(id)
                    .is_some_and(|o| evidence_proven(self, &o.evidence, &new_cov, global))
            });
        let (evidence_removed, evidence_tentative_removed) =
            split_removed(&old_ev, &new_ev, |id| {
                evidence_proven(self, id, &new_cov, global)
            });
        let (relationships_removed, relationships_tentative_removed) =
            split_removed(&old_rel, &new_rel, |id| {
                self.relationships.get(id).is_some_and(|r| {
                    if r.evidence.is_empty() {
                        global
                    } else {
                        r.evidence
                            .iter()
                            .all(|eid| evidence_proven(self, eid, &new_cov, global))
                    }
                })
            });
        let (conflicts_resolved, conflicts_tentative_resolved) =
            split_removed(&old_conf, &new_conf, |id| {
                self.conflicts.get(id).is_some_and(|conflict| {
                    let ids: Vec<_> = conflict.values.values().flat_map(|v| v.iter()).collect();
                    !ids.is_empty()
                        && ids.into_iter().all(|oid| {
                            self.observations.get(oid).is_some_and(|o| {
                                evidence_proven(self, &o.evidence, &new_cov, global)
                            })
                        })
                })
            });
        let coverage_changed: BTreeSet<String> = old_cov
            .keys()
            .chain(new_cov.keys())
            .filter(|key| old_cov.get(*key) != new_cov.get(*key))
            .map(|key| {
                if key.0 == 0 {
                    key.2.clone()
                } else {
                    format!("{key:?}")
                }
            })
            .collect();

        ChangeSet {
            added: new_assets.difference(&old_assets).cloned().collect(),
            removed,
            tentative_removed,
            changed: old_assets
                .intersection(&new_assets)
                .filter(|id| self.assets.get(*id) != newer.assets.get(*id))
                .cloned()
                .collect(),
            unchanged: old_assets
                .intersection(&new_assets)
                .filter(|id| self.assets.get(*id) == newer.assets.get(*id))
                .cloned()
                .collect(),
            observations_added: new_obs.difference(&old_obs).cloned().collect(),
            observations_removed,
            observations_tentative_removed,
            observations_changed: old_obs
                .intersection(&new_obs)
                .filter(|id| self.observations.get(*id) != newer.observations.get(*id))
                .cloned()
                .collect(),
            evidence_added: new_ev.difference(&old_ev).cloned().collect(),
            evidence_removed,
            evidence_tentative_removed,
            confidence_changed: old_ev
                .intersection(&new_ev)
                .filter(|id| {
                    self.evidence.get(*id).map(|e| e.confidence)
                        != newer.evidence.get(*id).map(|e| e.confidence)
                })
                .cloned()
                .collect(),
            relationships_added: new_rel.difference(&old_rel).cloned().collect(),
            relationships_removed,
            relationships_tentative_removed,
            relationships_changed: old_rel
                .intersection(&new_rel)
                .filter(|id| self.relationships.get(*id) != newer.relationships.get(*id))
                .cloned()
                .collect(),
            conflicts_changed: old_conf
                .intersection(&new_conf)
                .filter(|id| self.conflicts.get(*id) != newer.conflicts.get(*id))
                .cloned()
                .collect(),
            coverage_changed,
            conflicts_introduced: new_conf.difference(&old_conf).cloned().collect(),
            conflicts_resolved,
            conflicts_tentative_resolved,
        }
    }
}
