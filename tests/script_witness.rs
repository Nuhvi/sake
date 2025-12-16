use sake::script_witness::*;

#[test]
fn script_witness() {
    let cases = vec![
        vec![vec![vec![]], vec![vec![1]]],
        vec![vec![vec![2]], vec![vec![1]]],
    ];

    for stacks in cases {
        let encoded = encode(&stacks);

        let parsed = parse(&encoded).unwrap();

        assert_eq!(parsed, stacks);
    }
}
