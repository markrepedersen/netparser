use netparse::layer2::datalink::Frame;
use tui::{layout::Constraint, widgets::TableState};

#[allow(dead_code)]
pub struct StatefulTable {
    pub state: TableState,
    pub headers: Vec<String>,
    pub widths: Vec<Constraint>,
    pub records: Vec<Vec<String>>,
    pub frames: Vec<Frame>,
}

impl StatefulTable {
    pub fn new() -> StatefulTable {
        StatefulTable {
            state: TableState::default(),
            headers: vec![],
            widths: vec![],
            records: vec![],
            frames: vec![],
        }
    }

    pub fn push(&mut self, item: String, header: String, width: Constraint, index: usize) {
        if let Some(rec) = self.records.get_mut(index) {
            rec.push(item);
        } else {
            let rec = vec![item];
            self.records.push(rec);
        }
        if !self.headers.contains(&header) {
            self.headers.push(header);
            self.widths.push(width);
        }
    }

    pub fn get_selected(&self) -> Option<usize> {
        self.state.selected()
    }

    pub fn show_frame(&self) {
        if let Some(i) = self.get_selected() {
            if let Some(frame) = self.frames.get(i) {}
        }
    }

    pub fn next(&mut self, long: bool) {
        let i = match self.state.selected() {
            Some(i) => {
                if i >= self.records.len() - 1 {
                    0
                } else {
                    if long {
                        i + 10
                    } else {
                        i + 1
                    }
                }
            }
            None => 0,
        };
        self.state.select(Some(i));
    }

    pub fn previous(&mut self, long: bool) {
        let i = match self.state.selected() {
            Some(i) => {
                if i == 0 {
                    self.records.len() - 1
                } else {
                    if long {
                        i - 10
                    } else {
                        i - 1
                    }
                }
            }
            None => 0,
        };
        self.state.select(Some(i));
    }
}
