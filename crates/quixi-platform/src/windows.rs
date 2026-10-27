//! Windows desktop services. All results come from the OS; failures propagate.
use anyhow::{bail, Result};
use base64::Engine;
use enigo::{Button, Coordinate, Direction, Enigo, Key, Keyboard, Mouse, Settings};
use screenshots::Screen;
use std::io::Cursor;

pub fn displays() -> Vec<super::DisplayInfo> {
    Screen::all()
        .unwrap_or_default()
        .iter()
        .map(|screen| {
            let d = screen.display_info;
            super::DisplayInfo {
                id: d.id,
                name: format!("Display {}", d.id),
                width: d.width,
                height: d.height,
                scale_factor: f64::from(d.scale_factor),
                is_primary: d.is_primary,
            }
        })
        .collect()
}

pub fn screenshot(region: Option<(i32, i32, i32, i32)>) -> Result<String> {
    let screen = if let Some((x, y, _, _)) = region {
        Screen::from_point(x, y)?
    } else {
        Screen::all()?
            .into_iter()
            .find(|s| s.display_info.is_primary)
            .ok_or_else(|| anyhow::anyhow!("No interactive display is available"))?
    };
    let pixels = if let Some((x, y, right, bottom)) = region {
        if right <= x || bottom <= y {
            bail!("Screenshot region must have positive dimensions");
        }
        screen.capture_area(
            x - screen.display_info.x,
            y - screen.display_info.y,
            (right - x) as u32,
            (bottom - y) as u32,
        )?
    } else {
        screen.capture()?
    };
    let mut bytes = Cursor::new(Vec::new());
    pixels.write_to(&mut bytes, image::ImageOutputFormat::Png)?;
    Ok(base64::engine::general_purpose::STANDARD.encode(bytes.into_inner()))
}

pub fn input() -> Result<Enigo> {
    Ok(Enigo::new(&Settings::default())?)
}

pub fn cursor() -> Result<(f64, f64)> {
    let (x, y) = input()?.location()?;
    Ok((f64::from(x), f64::from(y)))
}

pub fn move_mouse(x: f64, y: f64) -> Result<()> {
    input()?.move_mouse(x as i32, y as i32, Coordinate::Abs)?;
    Ok(())
}

pub fn click(x: f64, y: f64, button: &str, count: i64) -> Result<()> {
    let mut enigo = input()?;
    enigo.move_mouse(x as i32, y as i32, Coordinate::Abs)?;
    let button = match button {
        "right" => Button::Right,
        "middle" => Button::Middle,
        _ => Button::Left,
    };
    for _ in 0..count.clamp(1, 3) {
        enigo.button(button, Direction::Click)?;
    }
    Ok(())
}

pub fn button(down: bool) -> Result<()> {
    // Separate mouse-down/up requests must preserve the held button between calls.
    Enigo::new(&Settings {
        release_keys_when_dropped: false,
        ..Settings::default()
    })?.button(
        Button::Left,
        if down {
            Direction::Press
        } else {
            Direction::Release
        },
    )?;
    Ok(())
}

pub fn drag(x: f64, y: f64, end_x: f64, end_y: f64) -> Result<()> {
    let mut enigo = input()?;
    enigo.move_mouse(x as i32, y as i32, Coordinate::Abs)?;
    enigo.button(Button::Left, Direction::Press)?;
    let moved = enigo.move_mouse(end_x as i32, end_y as i32, Coordinate::Abs);
    enigo.button(Button::Left, Direction::Release)?;
    moved?;
    Ok(())
}

pub fn text(text: &str) -> Result<()> {
    input()?.text(text)?;
    Ok(())
}

pub fn key(combo: &str, repeat: u32) -> Result<()> {
    let mut enigo = input()?;
    let lower = combo.to_lowercase();
    let parts: Vec<_> = lower.split('+').collect();
    let key = match *parts.last().unwrap_or(&"") {
        "enter" | "return" => Key::Return,
        "esc" | "escape" => Key::Escape,
        "tab" => Key::Tab,
        "space" => Key::Space,
        "backspace" => Key::Backspace,
        "delete" => Key::Delete,
        "up" => Key::UpArrow,
        "down" => Key::DownArrow,
        "left" => Key::LeftArrow,
        "right" => Key::RightArrow,
        "home" => Key::Home,
        "end" => Key::End,
        "pageup" => Key::PageUp,
        "pagedown" => Key::PageDown,
        s if s.chars().count() == 1 => Key::Unicode(s.chars().next().unwrap()),
        _ => bail!("Unsupported key: {combo}"),
    };
    let mut modifiers = Vec::new();
    for part in &parts[..parts.len().saturating_sub(1)] {
        modifiers.push(match *part {
            "ctrl" | "control" => Key::Control,
            "shift" => Key::Shift,
            "alt" | "option" => Key::Alt,
            "win" | "meta" | "cmd" => Key::Meta,
            _ => bail!("Unknown modifier: {part}"),
        });
    }
    // Release every held modifier even when an individual input call fails.
    let result = (|| -> Result<()> {
        for modifier in &modifiers {
            enigo.key(*modifier, Direction::Press)?;
        }
        for _ in 0..repeat.clamp(1, 20) {
            enigo.key(key, Direction::Click)?;
        }
        Ok(())
    })();
    for modifier in modifiers.into_iter().rev() {
        let _ = enigo.key(modifier, Direction::Release);
    }
    result
}

pub fn log_input(result: Result<()>) {
    if let Err(error) = result {
        tracing::error!("Windows input failed: {error}");
    }
}
