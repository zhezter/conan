use ratatui::{
    Frame,
    layout::Constraint,
    style::{Color, Style},
    symbols::border,
    text::{Line, Span},
    widgets::{Block, Borders},
};

use crate::App;

pub trait ConfirmScreen {
    fn render_confirmation(
        &self,
        f: &mut Frame<'_>,
        text: &str,
        options: &[String],
        selected: &usize,
    );
}

impl ConfirmScreen for App {
    fn render_confirmation(
        &self,
        f: &mut Frame<'_>,
        text: &str,
        options: &[String],
        selected: &usize,
    ) {
        let area = f.area();
        let con_area = area
            .centered_vertically(Constraint::Max(5))
            .centered_horizontally(Constraint::Max(30));
        let mut options_texts = Vec::new();
        for (i, o) in options.iter().enumerate() {
            let mut text = String::from(" ");
            text.push_str(o);
            text.push(' ');
            let style = if *selected == i {
                Style::new().bg(Color::LightBlue)
            } else {
                Style::default()
            };
            let span = Span::from(text).style(style);
            options_texts.push(span);
        }
        let block = Block::new()
            .title(" Confirm ")
            .borders(Borders::ALL)
            .border_set(border::ROUNDED)
            .title_bottom(Line::default().spans(options_texts).right_aligned());
        let line = Line::from(text).centered();
        let line_area = block.inner(con_area);
        f.render_widget(block, con_area);
        f.render_widget(line, line_area);
    }
}
