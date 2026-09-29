use super::BranchReport;

pub fn format_branch_report(report: &BranchReport) -> String {
    let mut lines = Vec::new();
    if let Some(plan) = &report.plan {
        let hop = match plan.hop {
            Some(index) => format!("hop {index}"),
            None => "hop ?".to_string(),
        };
        lines.push(format!(
            "node: {hop} (at-path {}) zone {} server {} query {}",
            plan.path, plan.zone, plan.server, plan.qname
        ));
        if plan.targets.is_empty() {
            lines.push("nothing to query at this cut".into());
        } else if report.dry_run {
            lines.push("would query:".into());
            for target in &plan.targets {
                lines.push(format!("  - {target}"));
            }
        } else {
            lines.push("queried:".into());
            for target in &plan.targets {
                lines.push(format!("  - {target}"));
            }
        }
    }
    if report.dry_run {
        lines.push("dry run: no queries issued".into());
    } else if report.nodes_added == 0 {
        lines.push("no nodes added".into());
    } else {
        lines.push(format!("added {} node(s)", report.nodes_added));
        if let Some(updated_at) = &report.updated_at {
            lines.push(format!("updated_at: {updated_at}"));
        }
    }
    for warning in &report.warnings {
        lines.push(format!("warning: {warning}"));
    }
    if report.budget_truncated {
        lines.push("warning: per-action query cap reached".into());
    }
    lines.join("\n")
}
