use ratatui::{
    Frame,
    layout::Constraint,
    style::Stylize,
    symbols::border,
    text::{Line, Span},
    widgets::{Block, Borders},
};

use crate::App;

pub trait ConfirmScreen {
    fn render_confirmation(&self, f: &mut Frame<'_>, text: &str, yes_selected: &bool);
}

impl ConfirmScreen for App {
    fn render_confirmation(&self, f: &mut Frame<'_>, text: &str, yes_selected: &bool) {
        let area = f.area();
        let con_area = area
            .centered_vertically(Constraint::Max(5))
            .centered_horizontally(Constraint::Max(30));
        let mut options = vec![];
        if *yes_selected {
            options.push(Span::from("Yes").on_blue());
            options.push(Span::from("No"));
        } else {
            options.push(Span::from("Yes"));
            options.push(Span::from("No").on_blue());
        }
        let block = Block::new()
            .title(" Confirm ")
            .borders(Borders::ALL)
            .border_set(border::ROUNDED)
            .title_bottom(Line::default().spans(options).right_aligned());
        let line = Line::from(text).centered();
        let line_area = block.inner(con_area);
        f.render_widget(block, con_area);
        f.render_widget(line, line_area);
    }
}
