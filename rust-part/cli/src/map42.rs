use log::info;
use petgraph::graphmap::DiGraphMap;
use pgp_sig2dot::structure::{GraphNodeUid, OpenPgpSig};
use rustworkx_core::centrality::betweenness_centrality;
use serde::Serialize;
use serialize_display_adapter_macro_derive::JsonSerializeDisplayAdapter;
use std::time::SystemTime;

/// https://bgp-data.strexp.net/graph/ipv4.json
#[derive(Debug, Serialize, JsonSerializeDisplayAdapter)]
struct Map42Data {
    created: u64,
    nodes: Vec<Map42Node>,
    edges: Vec<Map42Edge>,
}

#[derive(Debug, Clone, Serialize)]
struct Map42Node {
    asn: String,
    name: String,
    id: String,
    color: String,
    size: f32,
    centrality: f32,
}

#[derive(Debug, Clone, Serialize)]
struct Map42Edge {
    #[serde(rename = "sourceID")]
    source_id: String,
    #[serde(rename = "targetID")]
    target_id: String,
}

// https://github.com/strexp/dn42bgp/blob/main/core/graph.py
pub(crate) fn print_map42(graph: DiGraphMap<GraphNodeUid, &OpenPgpSig>) {
    let max_neighbors: f32 = graph
        .nodes()
        .fold(0, |a, b| a.max(graph.neighbors(b).count())) as f32;

    info!("Max neighbors: {}", max_neighbors);

    let _centralities = betweenness_centrality(&graph, false, true, 50);

    let nodes = graph
        .nodes()
        .map(|node| {
            let neighbor_ratio: f32 = (graph.neighbors(node).count() as f32) / max_neighbors;

            //let cent_val: f32 =
            //     *_centralities.get_item(graph.to_index(node)).unwrap_or(&-1.0) as f32;
            let cent_val: f32 = neighbor_ratio / 100.0;

            let pcentrality = if cent_val >= 0.0 {
                (cent_val + 0.0001) * 500.0
            } else {
                0.05
            };
            let size = (pcentrality.powf(0.3) / 500.0) * 1000.0 + 1.0;

            Map42Node {
                asn: node.fingerprint.to_string(),
                name: node.uid.to_string(),
                id: petgraph::visit::NodeIndexable::to_index(&graph, node).to_string(),
                color: gradient_color(neighbor_ratio, vec![(100, 100, 100), (0, 0, 0)]),
                size,
                centrality: cent_val,
            }
        })
        .collect();

    let map42_data = Map42Data {
        created: SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
        nodes,
        edges: graph
            .all_edges()
            .map(|edge| Map42Edge {
                source_id: petgraph::visit::NodeIndexable::to_index(&graph, edge.0).to_string(),
                target_id: petgraph::visit::NodeIndexable::to_index(&graph, edge.1).to_string(),
            })
            .collect(),
    };

    println!("{}", map42_data)
}

fn gradient_color(ratio: f32, colors: Vec<(u32, u32, u32)>) -> String {
    let jump = 1.0 / (colors.len() as f32 - 1.0);
    let mut gap_num = (ratio / (jump + 1e-7)) as usize;

    if gap_num >= (colors.len() - 1) {
        gap_num = colors.len() - 2;
    }

    let c1 = colors[gap_num];
    let c2 = colors[gap_num + 1];

    let local_ratio = (ratio - (gap_num as f32) * jump) * ((colors.len() - 1) as f32);

    let r = c1.0 + (c2.0 as f32 - c1.0 as f32 * local_ratio) as u32;
    let g = c1.1 + (c2.1 as f32 - c2.1 as f32 * local_ratio) as u32;
    let b = c1.2 + (c2.2 as f32 - c2.2 as f32 * local_ratio) as u32;

    format!("#{:02x}{:02x}{:02x}", r, g, b)
}
