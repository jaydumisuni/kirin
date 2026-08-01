//! Deterministic Xray policy primitives.
//!
//! This crate deliberately has no model or network dependency. The first-run
//! Python runtime performs evidence collection and report generation; this
//! Rust spine freezes the authority boundary and certification rules that will
//! move closer to transports as Xray grows.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    Observed,
    Corroborated,
    Inferred,
    Conflicted,
    Certified,
    Unknown,
    Blocked,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PrivateForcePlan {
    pub waves: u8,
    pub privates_per_wave: u8,
}

impl PrivateForcePlan {
    pub const fn srg_ten_for_two() -> Self {
        Self {
            waves: 2,
            privates_per_wave: 10,
        }
    }

    pub const fn total(self) -> u16 {
        self.waves as u16 * self.privates_per_wave as u16
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Evaluation {
    pub score: i16,
    pub hard_contradiction: bool,
    pub mandatory_proof_missing: bool,
    pub identity_gate_failed: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReviveWriteGate {
    pub identity_verified: bool,
    pub payload_verified: bool,
    pub block_path_verified: bool,
    pub operator_confirmed: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FirmwarePackageStatus {
    Ready,
    NeedsExtraction,
    Incomplete,
    Unverified,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReviveStageStatus {
    Prepared,
    Blocked,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReviveStageGate {
    pub device_verified: bool,
    pub artifact_set_complete: bool,
    pub partition_map_from_profile: bool,
    pub prior_stage_verified: bool,
}

/// Apply model-independent Xray certification policy.
///
/// Mandatory proof and hard contradictions cap the result even when a score is
/// high. Identity-gate failures block the investigation from authorizing any
/// identity-dependent operation.
pub const fn classify(evaluation: Evaluation) -> Status {
    if evaluation.identity_gate_failed {
        return Status::Blocked;
    }
    if evaluation.hard_contradiction {
        return Status::Conflicted;
    }
    if evaluation.mandatory_proof_missing {
        if evaluation.score >= 45 {
            return Status::Inferred;
        }
        return Status::Unknown;
    }
    if evaluation.score >= 90 {
        Status::Certified
    } else if evaluation.score >= 70 {
        Status::Corroborated
    } else if evaluation.score >= 45 {
        Status::Inferred
    } else if evaluation.score > 0 {
        Status::Observed
    } else {
        Status::Unknown
    }
}

/// Xray first-run never authorizes writes. Repair engines remain separate.
pub const fn write_authorized() -> bool {
    false
}

/// Models can add reasoning power, but the deterministic core does not require one.
pub const fn model_required() -> bool {
    false
}

/// Xray can prepare revive plans, but the evidence core cannot authorize writes.
///
/// The booleans are still modeled so future repair engines can prove every gate
/// before handing off to a separate authority. This function intentionally
/// returns false even when every gate is true.
pub const fn revive_write_authorized(_gate: ReviveWriteGate) -> bool {
    false
}

/// Classify catalog evidence without turning package presence into flash authority.
pub const fn classify_firmware_package(
    signature_known: bool,
    package_complete: bool,
    verification_metadata_complete: bool,
) -> FirmwarePackageStatus {
    if !signature_known {
        FirmwarePackageStatus::Unverified
    } else if !package_complete {
        FirmwarePackageStatus::Incomplete
    } else if !verification_metadata_complete {
        FirmwarePackageStatus::NeedsExtraction
    } else {
        FirmwarePackageStatus::Ready
    }
}

/// Prepare a recipe stage only when its deterministic evidence gates are complete.
/// This does not grant write authority.
pub const fn classify_revive_stage(gate: ReviveStageGate) -> ReviveStageStatus {
    if gate.device_verified
        && gate.artifact_set_complete
        && gate.partition_map_from_profile
        && gate.prior_stage_verified
    {
        ReviveStageStatus::Prepared
    } else {
        ReviveStageStatus::Blocked
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ten_for_two_is_twenty_privates() {
        assert_eq!(PrivateForcePlan::srg_ten_for_two().total(), 20);
    }

    #[test]
    fn missing_silicon_proof_cannot_certify() {
        assert_eq!(
            classify(Evaluation {
                score: 95,
                hard_contradiction: false,
                mandatory_proof_missing: true,
                identity_gate_failed: false,
            }),
            Status::Inferred
        );
    }

    #[test]
    fn hard_contradiction_wins_over_score() {
        assert_eq!(
            classify(Evaluation {
                score: 100,
                hard_contradiction: true,
                mandatory_proof_missing: false,
                identity_gate_failed: false,
            }),
            Status::Conflicted
        );
    }

    #[test]
    fn identity_gate_blocks() {
        assert_eq!(
            classify(Evaluation {
                score: 100,
                hard_contradiction: false,
                mandatory_proof_missing: false,
                identity_gate_failed: true,
            }),
            Status::Blocked
        );
    }

    #[test]
    fn authority_boundary_is_frozen() {
        assert!(!write_authorized());
        assert!(!model_required());
    }

    #[test]
    fn revive_plans_do_not_authorize_writes() {
        assert!(!revive_write_authorized(ReviveWriteGate {
            identity_verified: true,
            payload_verified: true,
            block_path_verified: true,
            operator_confirmed: true,
        }));
    }

    #[test]
    fn firmware_catalog_requires_package_and_metadata() {
        assert_eq!(
            classify_firmware_package(true, true, true),
            FirmwarePackageStatus::Ready
        );
        assert_eq!(
            classify_firmware_package(true, true, false),
            FirmwarePackageStatus::NeedsExtraction
        );
        assert_eq!(
            classify_firmware_package(true, false, false),
            FirmwarePackageStatus::Incomplete
        );
        assert_eq!(
            classify_firmware_package(false, true, true),
            FirmwarePackageStatus::Unverified
        );
    }

    #[test]
    fn carried_recipe_requires_every_stage_gate() {
        assert_eq!(
            classify_revive_stage(ReviveStageGate {
                device_verified: true,
                artifact_set_complete: true,
                partition_map_from_profile: true,
                prior_stage_verified: true,
            }),
            ReviveStageStatus::Prepared
        );
        assert_eq!(
            classify_revive_stage(ReviveStageGate {
                device_verified: true,
                artifact_set_complete: true,
                partition_map_from_profile: false,
                prior_stage_verified: true,
            }),
            ReviveStageStatus::Blocked
        );
        assert!(!revive_write_authorized(ReviveWriteGate {
            identity_verified: true,
            payload_verified: true,
            block_path_verified: true,
            operator_confirmed: true,
        }));
    }
}
