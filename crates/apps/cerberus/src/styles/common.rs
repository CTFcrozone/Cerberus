#![allow(unused)]
use ratatui::style::{Color, Style, Stylize};

// - Ratatui site: https://ratatui.rs/
//     - Paragraph / Text - https://ratatui.rs/recipes/widgets/paragraph/
//     - Block - https://ratatui.rs/recipes/widgets/block/
//
// - Terminal colors: https://en.wikipedia.org/wiki/ANSI_escape_code#8-bit

// -- Bkg Colors
pub const CLR_BKG_LIGHT: Color = Color::Indexed(240);
pub const CLR_BKG_GRAY: Color = Color::Indexed(238);
pub const CLR_BKG_GRAY_DARK: Color = Color::Indexed(236);
pub const CLR_BKG_GRAY_DARKER: Color = Color::Indexed(234);
pub const CLR_BKG_BLACK: Color = Color::Indexed(0);

pub const CLR_BKG_PRIME: Color = Color::Indexed(12);

pub const CLR_BKG_LBL: Color = CLR_BKG_GRAY_DARK;
pub const CLR_BKG_LBL_DARK: Color = CLR_BKG_BLACK;
pub const CLR_TXT_600: Color = Color::Indexed(250);
pub const CLR_BKG_ACT: Color = Color::Indexed(236);
pub const CLR_BKG_SEL: Color = Color::Indexed(15);

pub const CLR_BKG_WHITE: Color = Color::Indexed(255);

// -- Txt Colors

pub const CLR_TXT_300: Color = Color::Indexed(250);
pub const CLR_TXT_400: Color = Color::Indexed(252);
pub const CLR_TXT: Color = Color::Indexed(255);

pub const CLR_TXT_WHITE: Color = Color::Indexed(15);

pub const CLR_TXT_LBL: Color = CLR_TXT_300;
pub const CLR_TXT_SEL: Color = Color::Black;

pub const CLR_TXT_GREEN: Color = Color::Green;

pub const CLR_TXT_WAITING: Color = CLR_TXT_400;
pub const CLR_TXT_RUNNING: Color = Color::Blue;
pub const CLR_TXT_DONE: Color = Color::Green;

// -- Styles
pub const STL_TXT: Style = Style::new();

pub const STL_TXT_LBL: Style = Style::new().fg(CLR_TXT_LBL).bg(CLR_BKG_LBL);
pub const STL_TXT_VAL: Style = Style::new().fg(CLR_TXT_WHITE);

pub const STL_TXT_LBL_DARK: Style = Style::new().fg(Color::Indexed(242)).bg(CLR_BKG_LBL_DARK);
pub const STL_TXT_VAL_DARK: Style = Style::new().fg(CLR_TXT_LBL);

pub const STL_TXT_ACT: Style = Style::new().fg(Color::White);
pub const STL_TXT_SEL: Style = Style::new().fg(Color::Blue);
pub const STL_TXT_ACTION: Style = Style::new().fg(Color::Blue);
pub const STL_TXT_ACTION_SELECTED: Style = Style::new().fg(Color::LightGreen);

pub const CLR_BKG_TAB_ACT: Color = CLR_BKG_GRAY_DARK;

pub const STL_TAB_DEFAULT: Style = Style::new().bg(CLR_BKG_GRAY_DARKER).fg(CLR_TXT_600);
pub const STL_TAB_ACTIVE: Style = Style::new().bg(CLR_BKG_TAB_ACT).fg(CLR_TXT_400);

pub const STL_NAV_ITEM_HIGHLIGHT: Style = Style::new().bg(CLR_BKG_SEL).fg(CLR_TXT_SEL);

// -- TABS
pub fn stl_tab_dft() -> Style {
	Style::new().bg(CLR_BKG_GRAY_DARKER).fg(CLR_TXT_300)
}

pub fn stl_tab_act() -> Style {
	Style::new().bg(CLR_BKG_TAB_ACT).fg(CLR_TXT_WHITE).bold()
}
