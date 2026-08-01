use xray_core::{
    model_required, revive_write_authorized, write_authorized, PrivateForcePlan, ReviveWriteGate,
};

fn main() {
    let plan = PrivateForcePlan::srg_ten_for_two();
    println!("Xray deterministic core 0.1.0");
    println!("SRG 10-for-2 privates: {}", plan.total());
    println!("write_authorized={}", write_authorized());
    println!(
        "revive_write_authorized={}",
        revive_write_authorized(ReviveWriteGate {
            identity_verified: false,
            payload_verified: false,
            block_path_verified: false,
            operator_confirmed: false,
        })
    );
    println!("model_required={}", model_required());
}
