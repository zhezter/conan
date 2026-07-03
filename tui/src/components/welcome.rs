use ratatui::{
    Frame,
    layout::{Constraint, HorizontalAlignment},
    symbols::border,
    text::Line,
    widgets::{Block, Borders},
};

use crate::App;

pub trait WelcomeScreen {
    fn render_welcome(&self, f: &mut Frame<'_>);
}
impl WelcomeScreen for App {
    fn render_welcome(&self, f: &mut Frame<'_>) {
        let area = f.area();
        let rect = area
            .centered_horizontally(Constraint::Length(30))
            .centered_vertically(Constraint::Max(3));
        let block = Block::new()
            .border_set(border::DOUBLE)
            .borders(Borders::ALL);
        let line = Line::from("Welcome").alignment(HorizontalAlignment::Center);
        let line_rect = block.inner(rect);
        f.render_widget(line, line_rect);
        f.render_widget(block, rect);
    }
}
