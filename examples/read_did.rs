use anyhow::Result;
use did_btcr2::resolver::ResolverState;
use did_btcr2::{Document, ResolutionOptions, document::SidecarData};
use std::collections::HashMap;

fn main() -> Result<()> {
    let resolution_options = ResolutionOptions {
        sidecar_data: Some(SidecarData {
            blockchain_rpc_uri: Some("https://mutinynet.com/api".into()),
            ..Default::default()
        }),
        ..Default::default()
    };

    let agent = ureq::agent();
    let did =
        "did:btcr2:k1q5pqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqsx6n2m7".parse()?;
    let mut fsm = Document::read(&did, resolution_options)?;

    // Drive the blockchain traversal state machine forward.
    let document = loop {
        match fsm.resolve()? {
            // The state machine delegates blockchain requests to us.
            ResolverState::Requests(next_state, beacons) => {
                let mut responses = HashMap::new();

                for (beacon_type, requests) in beacons {
                    for req in requests {
                        let mut resp = agent.run(req)?;

                        let entry: &mut Vec<_> = responses.entry(beacon_type).or_default();
                        entry.extend(resp.body_mut().read_json::<Vec<_>>()?);
                    }
                }

                fsm = next_state.process_responses(responses);
            }

            // And eventually yields a resolved document.
            ResolverState::Resolved(document) => break document,
        }
    };

    println!("Resolved document: {document:#?}");

    Ok(())
}
