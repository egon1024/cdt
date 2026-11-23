#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PickerState {
    Closed,
    Open { menu: PickerMenu, selection: usize },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PickerMenu {
    Root,
    Presets,
    Saved,
    Recent,
    ComposeField,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PickerAction {
    SelectPreset(String),
    SelectSaved(String),
    SelectRecent(String),
    ClearFilter,
    ComposeField(String),
    Close,
}

pub fn apply_picker_action(state: &mut PickerState, action: PickerAction) -> Option<String> {
    match action {
        PickerAction::Close => {
            *state = PickerState::Closed;
            None
        }
        PickerAction::ClearFilter => {
            *state = PickerState::Closed;
            Some(String::new())
        }
        PickerAction::SelectPreset(name)
        | PickerAction::SelectSaved(name)
        | PickerAction::SelectRecent(name) => {
            *state = PickerState::Closed;
            Some(name)
        }
        PickerAction::ComposeField(expr) => {
            *state = PickerState::Closed;
            Some(expr)
        }
    }
}

#[allow(dead_code)] // live TUI entry hook for phase 2 picker
pub fn picker_key(state: &mut PickerState, key: char) -> Option<PickerAction> {
    match state {
        PickerState::Closed if key == 'f' => {
            *state = PickerState::Open {
                menu: PickerMenu::Root,
                selection: 0,
            };
            None
        }
        PickerState::Open { menu, selection } => match key {
            'q' | '\u{1b}' => Some(PickerAction::Close),
            'c' => Some(PickerAction::ClearFilter),
            'p' => {
                *menu = PickerMenu::Presets;
                *selection = 0;
                None
            }
            's' => {
                *menu = PickerMenu::Saved;
                *selection = 0;
                None
            }
            'r' => {
                *menu = PickerMenu::Recent;
                *selection = 0;
                None
            }
            'e' => {
                *menu = PickerMenu::ComposeField;
                *selection = 0;
                None
            }
            '\n' | ' ' => match menu {
                PickerMenu::Presets => Some(PickerAction::SelectPreset("errors".into())),
                PickerMenu::Saved => Some(PickerAction::SelectSaved("leaks".into())),
                PickerMenu::Recent => Some(PickerAction::SelectRecent("+qtype=PTR".into())),
                PickerMenu::ComposeField => Some(PickerAction::ComposeField("+qname=.".into())),
                PickerMenu::Root => {
                    *menu = PickerMenu::Presets;
                    None
                }
            },
            _ => None,
        },
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn select_and_clear_filter() {
        let mut state = PickerState::Closed;
        assert!(picker_key(&mut state, 'f').is_none());
        assert!(matches!(
            state,
            PickerState::Open {
                menu: PickerMenu::Root,
                ..
            }
        ));
        assert!(picker_key(&mut state, 'p').is_none());
        let act = picker_key(&mut state, '\n').expect("choose preset");
        let label = apply_picker_action(&mut state, act).expect("label");
        assert_eq!(label, "errors");
        let cleared = apply_picker_action(&mut state, PickerAction::ClearFilter).expect("clear");
        assert!(cleared.is_empty());
        assert_eq!(state, PickerState::Closed);
    }
}
