use crate::capture::Event;
use crate::table::*;

use crossbeam::channel::Receiver;
use io::stdout;
use netparse::layer2::datalink::Frame;
use std::{
    io,
    sync::{Arc, Mutex, MutexGuard},
};
use termion::{input::MouseTerminal, raw::IntoRawMode, screen::AlternateScreen};
use tui::backend::TermionBackend;
use tui::{
    backend::Backend,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    widgets::{Block, BorderType, Borders, Paragraph, Row, Table, Text},
    Terminal,
};

fn draw_frame_excerpt<B: Backend>(f: &mut tui::Frame<B>, frame: &Frame, area: Rect) {
    use Frame::*;
    match frame {
        Ethernet(frame) => {
            let text = [
                Text::styled(
                    format!("IP_SRC: {:?}\n", frame.src),
                    Style::default().fg(Color::White),
                ),
                Text::styled(
                    format!("IP_DST: {:?}\n", frame.dst),
                    Style::default().fg(Color::White),
                ),
                Text::styled(
                    format!("IP_DST: {:?}\n", frame.dst),
                    Style::default().fg(Color::White),
                ),
            ];
            let block = Block::default()
                .borders(Borders::ALL)
                .title("Frame View")
                .title_style(Style::default().fg(Color::Magenta).modifier(Modifier::BOLD));
            let paragraph = Paragraph::new(text.iter()).block(block).wrap(true);
            f.render_widget(paragraph, area);
        }
        Dot11(frame) => {}
    };
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
        vec![Constraint::Percentage(50), Constraint::Percentage(50)]
    } else {
        vec![Constraint::Percentage(100)]
    };
    Layout::default()
        .direction(Direction::Vertical)
        .margin(1)
        .constraints(constraints)
        .split(f.size())
}

pub fn draw(
    table: &Arc<Mutex<StatefulTable>>,
    receiver: &Receiver<Event>,
) -> Result<(), io::Error> {
    let stdout = stdout().into_raw_mode()?;
    let stdout = MouseTerminal::from(stdout);
    let stdout = AlternateScreen::from(stdout);
    let backend = TermionBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    terminal.hide_cursor()?;

    loop {
        match receiver.recv() {
            Ok(Event::Disconnected) => {
                terminal.clear()?;
                std::process::exit(0);
            }
            Ok(Event::Selected) => terminal.draw(|mut f| {
                if let Ok(mut table) = table.lock() {
                    let chunks = get_rendering_area(&mut f, true);
                    draw_table(&mut f, &mut table, chunks[0]);
                    if let Some(i) = table.get_selected() {
                        if let Some(frame) = table.frames.get(i) {
                            draw_frame_excerpt(&mut f, &frame, chunks[1]);
                        }
                    }
                }
            })?,
            Ok(Event::Key) | Ok(Event::Tick) => terminal.draw(|mut f| {
                if let Ok(mut table) = table.lock() {
                    let chunks = get_rendering_area(&mut f, false);
                    draw_table(&mut f, &mut table, chunks[0]);
                }
            })?,
            _ => {}
        }
    }
}
