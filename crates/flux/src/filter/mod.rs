mod endpoints;
mod engine;
mod flags;
mod picker;
mod presets;
mod yaml;

pub use endpoints::{EndpointIndex, EndpointResolver, NoopResolver, StubResolver};
pub use engine::{
    CompareOp, CompiledFilter, EvalContext, FieldCond, FieldId, FilterHeader, FilterPredicate,
    MatchStats, Predicate, QrSelection, build_compiled, effective_qr, evaluate_predicate,
    predicate_requires_response, record_matches_qr,
};
pub use flags::{FilterParseError, parse_filter_flags};
pub use picker::{PickerAction, PickerMenu, PickerState, apply_picker_action, picker_key};
pub use presets::embedded_iana_tlds;
pub use presets::{PresetKind, preset_by_name, preset_label};
pub use yaml::{SavedFilterError, compile_saved_filter, load_named_filter, validate_filter_yaml};

pub fn filter_header_line(header: &FilterHeader, stats: &MatchStats) -> String {
    if header.is_empty() {
        return String::new();
    }
    let pct = if stats.total_observed == 0 {
        0.0
    } else {
        (stats.matched as f64) * 100.0 / (stats.total_observed as f64)
    };
    format!(
        "=== Filter: {} — {} of {} msgs ({pct:.1}%) | qr={qr} ===\n",
        header.label,
        stats.matched,
        stats.total_observed,
        qr = header.qr.as_str(),
    )
}
