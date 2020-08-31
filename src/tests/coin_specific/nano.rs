use serde::Deserialize;

use crate::coins::nano::engine::nano_rpc_maybe_empty;

#[test]
fn empty_string_response() {
    #[derive(Deserialize, PartialEq, Debug)]
    struct PendingResponse {
        #[serde(with = "nano_rpc_maybe_empty")]
        blocks: Vec<String>,
    }

    const TEST_CASES: &[(&str, &[&str])]= &[
        (r#"{"blocks": ""}"#, &[]),
        (r#"{"blocks": []}"#, &[]),
        (r#"{"blocks": ["foo"]}"#, &["foo"]),
        (r#"{"blocks": ["foo", "bar"]}"#, &["foo", "bar"]),
    ];

    for (s, expected) in TEST_CASES {
        let result: PendingResponse = serde_json::from_str(s).unwrap();
        assert_eq!(&result.blocks, expected);
    }
}
