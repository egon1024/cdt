use dns_resolve::{TraceNode, TraceTree};

use super::card::{HopCard, measure_card};

#[derive(Debug, Clone, PartialEq)]
pub struct PositionedCard {
    pub index: usize,
    pub x: f64,
    pub y: f64,
    pub width: f64,
    pub height: f64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TreeEdge {
    pub parent_index: usize,
    pub child_index: usize,
    pub dashed: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub struct TreeLayout {
    pub cards: Vec<PositionedCard>,
    pub edges: Vec<TreeEdge>,
    pub width: f64,
    pub height: f64,
}

const COL_GAP: f64 = 64.0;
const ROW_GAP: f64 = 14.0;
const PAD: f64 = 10.0;

pub fn layout_tree(cards: &[HopCard], tree: &TraceTree) -> TreeLayout {
    let mut sizes = Vec::with_capacity(cards.len());
    for card in cards {
        let (w, h) = measure_card(&card.hop, card.branch_label.as_deref());
        sizes.push((w, h));
    }

    let mut depth_width = std::collections::BTreeMap::new();
    for card in cards {
        let (w, _) = sizes[card.display_index];
        depth_width
            .entry(card.depth)
            .and_modify(|existing: &mut f64| *existing = existing.max(w))
            .or_insert(w);
    }

    let mut depth_x = std::collections::BTreeMap::new();
    let mut x_acc = PAD;
    for depth in depth_width.keys() {
        depth_x.insert(*depth, x_acc);
        x_acc += depth_width[depth] + COL_GAP;
    }

    let mut positions = vec![(0.0, 0.0); cards.len()];
    let mut cursor_y = PAD;

    struct PlaceCtx<'a> {
        tree_index: usize,
        depth_x: &'a std::collections::BTreeMap<usize, f64>,
        sizes: &'a [(f64, f64)],
        cards: &'a [HopCard],
        positions: &'a mut [(f64, f64)],
        cursor_y: &'a mut f64,
    }

    fn place(node: &TraceNode, path: &[usize], depth: usize, ctx: &mut PlaceCtx<'_>) {
        let card_index = ctx
            .cards
            .iter()
            .position(|card| card.path.tree == ctx.tree_index && card.path.path == path)
            .expect("card exists for node");
        let (_w, h) = ctx.sizes[card_index];
        let x = *ctx.depth_x.get(&depth).unwrap_or(&PAD);

        if node.children.is_empty() {
            let y = *ctx.cursor_y;
            ctx.positions[card_index] = (x, y);
            *ctx.cursor_y += h + ROW_GAP;
            return;
        }

        for (index, child) in node.children.iter().enumerate() {
            let mut child_path = path.to_vec();
            child_path.push(index);
            place(child, &child_path, depth + 1, ctx);
        }

        let child_indices: Vec<usize> = node
            .children
            .iter()
            .enumerate()
            .map(|(index, _)| {
                let mut child_path = path.to_vec();
                child_path.push(index);
                ctx.cards
                    .iter()
                    .position(|card| {
                        card.path.tree == ctx.tree_index && card.path.path == child_path
                    })
                    .expect("child card")
            })
            .collect();

        let top = ctx.positions[child_indices[0]].1;
        let bottom = child_indices
            .iter()
            .map(|idx| ctx.positions[*idx].1 + ctx.sizes[*idx].1)
            .fold(0.0, f64::max);
        let y = (top + bottom) / 2.0 - h / 2.0;
        ctx.positions[card_index] = (x, y);
    }

    let tree_index = cards.first().map(|c| c.path.tree).unwrap_or(0);
    place(
        &tree.root,
        &[],
        0,
        &mut PlaceCtx {
            tree_index,
            depth_x: &depth_x,
            sizes: &sizes,
            cards,
            positions: &mut positions,
            cursor_y: &mut cursor_y,
        },
    );

    let min_y = positions
        .iter()
        .map(|(_, y)| *y)
        .fold(f64::INFINITY, f64::min);
    if min_y < PAD {
        let shift = PAD - min_y;
        for (_, y) in &mut positions {
            *y += shift;
        }
        cursor_y += shift;
    }

    let mut edges = Vec::new();
    fn collect_edges(
        node: &TraceNode,
        tree_index: usize,
        path: &[usize],
        parent_index: Option<usize>,
        cards: &[HopCard],
        edges: &mut Vec<TreeEdge>,
    ) {
        let card_index = cards
            .iter()
            .position(|card| card.path.tree == tree_index && card.path.path == path)
            .expect("card exists");
        if let Some(parent_index) = parent_index {
            edges.push(TreeEdge {
                parent_index,
                child_index: card_index,
                dashed: cards[card_index].is_branch,
            });
        }
        for (index, child) in node.children.iter().enumerate() {
            let mut child_path = path.to_vec();
            child_path.push(index);
            collect_edges(
                child,
                tree_index,
                &child_path,
                Some(card_index),
                cards,
                edges,
            );
        }
    }
    collect_edges(
        &tree.root,
        cards.first().map(|c| c.path.tree).unwrap_or(0),
        &[],
        None,
        cards,
        &mut edges,
    );

    let positioned: Vec<PositionedCard> = positions
        .into_iter()
        .enumerate()
        .map(|(index, (x, y))| PositionedCard {
            index,
            x,
            y,
            width: sizes[index].0,
            height: sizes[index].1,
        })
        .collect();

    let width = x_acc + PAD;
    let height = cursor_y + PAD;
    TreeLayout {
        cards: positioned,
        edges,
        width,
        height,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dns_resolve::{HopOutcome, NodeOrigin, TraceHop, TraceNode, TraceTree, TraceTreeRequest};

    use crate::export::card::build_cards;

    fn hop(zone: &str, server: &str, outcome: HopOutcome) -> TraceHop {
        TraceHop {
            zone: zone.into(),
            server: server.into(),
            server_name: Some(format!("{server}.example.net")),
            qname: "example.com.".into(),
            qtype: "A".into(),
            transport: "udp".into(),
            rtt_ms: 20,
            rcode: "NOERROR".into(),
            nsid: None,
            ede_code: None,
            ede_text: None,
            referral_ns: vec![],
            glue: vec![],
            response: Default::default(),
            from_cache: false,
            outcome,
        }
    }

    fn branching_tree() -> TraceTree {
        TraceTree {
            request: TraceTreeRequest {
                qname: "example.com.".into(),
                qtype: "A".into(),
                started_at: "2026-01-01T00:00:00Z".into(),
            },
            root: TraceNode {
                hop: hop(".", "198.41.0.4", HopOutcome::Referral),
                origin: NodeOrigin::Trace,
                children: vec![TraceNode {
                    hop: hop("com.", "192.41.162.30", HopOutcome::Referral),
                    origin: NodeOrigin::Trace,
                    children: vec![
                        TraceNode {
                            hop: hop("example.com.", "199.43.135.53", HopOutcome::Answered),
                            origin: NodeOrigin::Trace,
                            children: vec![],
                        },
                        TraceNode {
                            hop: hop("example.com.", "199.43.133.53", HopOutcome::Answered),
                            origin: NodeOrigin::Trace,
                            children: vec![],
                        },
                    ],
                }],
            },
            budget_truncated: false,
        }
    }

    fn boxes_overlap(a: &PositionedCard, b: &PositionedCard) -> bool {
        let ax2 = a.x + a.width;
        let ay2 = a.y + a.height;
        let bx2 = b.x + b.width;
        let by2 = b.y + b.height;
        a.x < bx2 && ax2 > b.x && a.y < by2 && ay2 > b.y
    }

    #[test]
    fn branching_layout_keeps_cards_within_padding() {
        let tree = branching_tree();
        let cards = build_cards(&tree, 0);
        let layout = layout_tree(&cards, &tree);
        let min_y = layout
            .cards
            .iter()
            .map(|card| card.y)
            .fold(f64::INFINITY, f64::min);
        assert!(
            min_y >= PAD,
            "card layout must not place nodes above padding (min_y={min_y})"
        );
    }

    #[test]
    fn branching_layout_has_no_overlapping_cards() {
        let tree = branching_tree();
        let cards = build_cards(&tree, 0);
        let layout = layout_tree(&cards, &tree);
        assert_eq!(layout.cards.len(), 4);
        for i in 0..layout.cards.len() {
            for j in (i + 1)..layout.cards.len() {
                assert!(
                    !boxes_overlap(&layout.cards[i], &layout.cards[j]),
                    "cards {i} and {j} overlap"
                );
            }
        }
    }

    #[test]
    fn branching_layout_emits_parent_child_edges() {
        let tree = branching_tree();
        let cards = build_cards(&tree, 0);
        let layout = layout_tree(&cards, &tree);
        assert_eq!(layout.edges.len(), 3);
        assert!(
            layout
                .edges
                .iter()
                .any(|edge| { edge.parent_index == 0 && edge.child_index == 1 && !edge.dashed })
        );
    }

    fn single_child_branch_tree() -> TraceTree {
        TraceTree {
            request: TraceTreeRequest {
                qname: "example.com.".into(),
                qtype: "A".into(),
                started_at: "2026-01-01T00:00:00Z".into(),
            },
            root: TraceNode {
                hop: hop(".", "198.41.0.4", HopOutcome::Referral),
                origin: NodeOrigin::Trace,
                children: vec![TraceNode {
                    hop: hop("com.", "192.41.162.30", HopOutcome::Referral),
                    origin: NodeOrigin::Trace,
                    children: vec![TraceNode {
                        hop: hop("example.com.", "199.43.135.53", HopOutcome::Answered),
                        origin: NodeOrigin::Trace,
                        children: vec![],
                    }],
                }],
            },
            budget_truncated: false,
        }
    }

    #[test]
    fn single_child_branch_keeps_root_below_padding() {
        let tree = single_child_branch_tree();
        let cards = build_cards(&tree, 0);
        let layout = layout_tree(&cards, &tree);
        let min_y = layout
            .cards
            .iter()
            .map(|card| card.y)
            .fold(f64::INFINITY, f64::min);
        assert!(
            min_y >= PAD,
            "single-child branch must not tuck parents under the header (min_y={min_y})"
        );
    }
}
