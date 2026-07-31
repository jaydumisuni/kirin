use xray_core::{model_required, write_authorized, PrivateForcePlan};

fn main() {
    let plan = PrivateForcePlan::srg_ten_for_two();
    println!("Xray deterministic core 0.1.0");
    println!("SRG 10-for-2 privates: {}", plan.total());
    println!("write_authorized={}", write_authorized());
    println!("model_required={}", model_required());
}
