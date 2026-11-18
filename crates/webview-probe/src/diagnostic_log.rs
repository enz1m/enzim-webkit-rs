use std::collections::VecDeque;

pub(crate) const LOG_CAPACITY: usize = 256;
pub(crate) const LOG_LINE_BYTES: usize = 2048;

#[derive(Debug, Default)]
pub(crate) struct DiagnosticLog {
    lines: VecDeque<String>,
}

impl DiagnosticLog {
    pub(crate) fn push(&mut self, mut line: String) {
        if line.len() > LOG_LINE_BYTES {
            let mut end = LOG_LINE_BYTES - "...".len();
            while !line.is_char_boundary(end) {
                end -= 1;
            }
            line.truncate(end);
            line.push_str("...");
        }
        if line.capacity() > LOG_LINE_BYTES {
            // Truncation alone retains the page-controlled allocation's capacity.
            line = line.into_boxed_str().into_string();
        }
        if self.lines.len() == LOG_CAPACITY {
            self.lines.pop_front();
        }
        self.lines.push_back(line);
    }

    pub(crate) fn iter(&self) -> impl DoubleEndedIterator<Item = &String> + ExactSizeIterator {
        self.lines.iter()
    }
}
