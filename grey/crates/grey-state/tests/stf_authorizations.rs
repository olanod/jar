//! STF test vectors for authorizations sub-transition (Section 8).

mod common;

use common::{hash_from_hex, parse_nested_hash_vecs};
use grey_state::authorizations::{AuthorizationInput, update_authorizations};
use grey_types::Hash;
use grey_types::config::Config;

fn run_authorizations_test(dir: &str, stem: &str) {
    run_authorizations_test_variant(dir, stem, "jar1");
}

/// Authorizations is param-independent between gp072_tiny and gp072_full: the
/// transition reads only `auth_pool_size` (O=8) and `auth_queue_size` (Q=80),
/// which are identical in both configs, and the core count comes from the
/// vector's `auth_pools.len()`. So `Config::full()` is correct for every
/// variant.
fn run_authorizations_test_variant(dir: &str, stem: &str, variant: &str) {
    let json = common::load_jar_test_variant(dir, stem, variant);
    let path = format!("{dir}/{stem}.{variant}");

    let input_json = &json["input"];
    let pre = &json["pre_state"];
    let post = &json["post_state"];

    // Parse input
    let slot = input_json["slot"].as_u64().unwrap() as u32;
    let auths: Vec<(u16, Hash)> = input_json["auths"]
        .as_array()
        .unwrap()
        .iter()
        .map(|a| {
            (
                a["core"].as_u64().unwrap() as u16,
                hash_from_hex(a["auth_hash"].as_str().unwrap()),
            )
        })
        .collect();

    // Parse pre-state pools and queues
    let mut auth_pools: Vec<Vec<Hash>> = parse_nested_hash_vecs(&pre["auth_pools"]);
    let auth_queues: Vec<Vec<Hash>> = parse_nested_hash_vecs(&pre["auth_queues"]);

    // Apply transition
    let config = Config::full();
    let input = AuthorizationInput { slot, auths };
    update_authorizations(&config, &mut auth_pools, &auth_queues, &input);

    // Parse expected post-state
    let expected_pools: Vec<Vec<Hash>> = parse_nested_hash_vecs(&post["auth_pools"]);

    // Compare
    assert_eq!(
        auth_pools.len(),
        expected_pools.len(),
        "pool count mismatch in {}",
        path
    );
    for (core, (got, exp)) in auth_pools.iter().zip(expected_pools.iter()).enumerate() {
        assert_eq!(got, exp, "auth pool mismatch for core {} in {}", core, path);
    }
}

const DIR: &str = "../../../spec/tests/vectors/authorizations";

stf_test!(
    test_stf_authorizations_1,
    "progress_authorizations-1",
    DIR,
    run_authorizations_test
);
stf_test!(
    test_stf_authorizations_2,
    "progress_authorizations-2",
    DIR,
    run_authorizations_test
);
stf_test!(
    test_stf_authorizations_3,
    "progress_authorizations-3",
    DIR,
    run_authorizations_test
);

discover_all_test!(DIR, run_authorizations_test);
discover_all_variant_test!(
    discover_all_gp072_tiny,
    DIR,
    run_authorizations_test_variant,
    "gp072_tiny"
);
discover_all_variant_test!(
    discover_all_gp072_full,
    DIR,
    run_authorizations_test_variant,
    "gp072_full"
);
