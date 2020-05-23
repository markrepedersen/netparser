use crate::capture::Event;
use crate::table::*;
use crossbeam::channel::Receiver;
use std::{
    io,
    sync::{Arc, Mutex, MutexGuard},
};
use tui::{
    backend::Backend,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    widgets::{Block, BorderType, Borders, Row, Table},
    Terminal,
};

fn draw_frame_excerpt<B: Backend>(
    f: &mut tui::Frame<B>,
    table: &MutexGuard<StatefulTable>,
    area: Rect,
) {
    let block = Block::default()
        .borders(Borders::ALL)
        .title("Footer")
        .title_style(Style::default().fg(Color::Magenta).modifier(Modifier::BOLD));
    f.render_widget(block, area);
}

fn draw_table<B: Backend>(
    f: &mut tui::Frame<B>,
    table: &mut MutexGuard<StatefulTable>,
    area: Rect,
) {
    let selected_style = Style::default()
        .fg(Color::White)
        .modifier(Modifier::BOLD | Modifier::ITALIC);
    let normal_style = Style::default().fg(Color::Blue).modifier(Modifier::ITALIC);
    let headers = table.headers.clone();
    let records = table.records.clone();
    let widths = table.widths.clone();
    let rows = records
        .iter()
        .map(|i| Row::StyledData(i.into_iter(), normal_style));
    let t = Table::new(headers.into_iter(), rows)
        .block(
            Block::default()
                .title("Packets")
                .title_style(
                    Style::default()
                        .fg(Color::DarkGray)
                        .modifier(Modifier::BOLD),
                )
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded),
        )
        .header_style(
            Style::default()
                .fg(Color::DarkGray)
                .modifier(Modifier::BOLD | Modifier::ITALIC),
        )
        .widths(&widths[..])
        .highlight_style(selected_style)
        .column_spacing(5)
        .highlight_symbol(">> ");

    if records.len() > 0 {
        f.render_stateful_widget(t, area, &mut table.state);
    }
}

fn get_rendering_area<B: Backend>(f: &mut tui::Frame<B>, footer: bool) -> Vec<Rect> {
    let constraints = if footer {
        vec![Constraint::Percentage(80), Constraint::Percentage(20)]
    } else {
        vec![Constraint::Percentage(100)]
    };
    Layout::default()
        .direction(Direction::Vertical)
        .margin(1)
        .constraints(constraints)
        .split(f.size())
}

pub fn draw<B: Backend>(
    terminal: &mut Terminal<B>,
    table: &Arc<Mutex<StatefulTable>>,
    receiver: &Receiver<Event>,
) -> Result<(), io::Error> {
    terminal.draw(|mut f| {
        if let Ok(mut table) = table.lock() {
            if let Ok(Event::Selected) = receiver.try_recv() {
                let chunks = get_rendering_area(&mut f, true);
                draw_table(&mut f, &mut table, chunks[0]);
                draw_frame_excerpt(&mut f, &table, chunks[1]);
            } else {
                let chunks = get_rendering_area(&mut f, false);
                draw_table(&mut f, &mut table, chunks[0]);
            }
        }
    })?;

    Ok(())
}
