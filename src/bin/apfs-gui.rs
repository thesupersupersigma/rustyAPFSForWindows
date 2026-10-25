//! Desktop app: lists APFS volumes on the computer's disks (and image files you open), and mounts
//! them as drive letters, read-write where possible.

#![windows_subsystem = "windows"]

use eframe::egui;
use rusty_apfs::mount::{self, Session};
use rusty_apfs::write::Writer;
use rusty_apfs::{Container, apfs_partitions};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

fn main() -> eframe::Result {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default().with_inner_size([760.0, 460.0]).with_title("rusty APFS"),
        ..Default::default()
    };
    eframe::run_native("rusty APFS", options, Box::new(|_| Ok(Box::new(App::new()))))
}

/// An APFS container: a GPT partition of a physical disk, or an image file.
struct Source {
    path: String,
    partition: Option<usize>,
    title: String,
    volumes: Vec<VolInfo>,
    error: Option<String>,
}

struct VolInfo {
    name: String,
    used: u64,
    encrypted: bool,
    snapshots: u64,
    read_only: bool,
    password: String,
}

struct Active {
    source: usize,
    vol: usize,
    letter: String,
    rw: bool,
    session: Session,
}

struct App {
    sources: Vec<Source>,
    active: Vec<Active>,
    /// One writer per container, shared by its mounted volumes; dropped when the last one unmounts.
    writers: HashMap<usize, Arc<Mutex<Writer>>>,
    status: String,
    admin: bool,
}

impl App {
    fn new() -> App {
        let mut app =
            App { sources: vec![], active: vec![], writers: HashMap::new(), status: String::new(), admin: is_admin() };
        app.scan_disks();
        // Images passed on the command line ("Open with", drag onto the exe).
        for path in std::env::args().skip(1) {
            let title =
                std::path::Path::new(&path).file_name().map_or(path.clone(), |n| n.to_string_lossy().into_owned());
            app.sources.push(load(path, None, title));
        }
        app
    }

    /// Finds APFS partitions on physical disks (needs administrator rights) and reloads the volume
    /// lists of everything shown. Sources are only ever added: mounts refer to them by index.
    fn scan_disks(&mut self) {
        for s in 0..self.sources.len() {
            if !self.active.iter().any(|a| a.source == s) {
                self.refresh(s);
            }
        }
        if !self.admin {
            return;
        }
        for n in 0..32 {
            let disk = format!(r"\\.\PhysicalDrive{n}");
            let Ok(parts) = apfs_partitions(&disk) else { continue };
            for (i, p) in parts.iter().enumerate() {
                if self.sources.iter().any(|s| s.path == disk && s.partition == Some(i)) {
                    continue;
                }
                let gib = p.size as f64 / (1u64 << 30) as f64;
                let title = format!("Disk {n}, partition {} \u{2014} {:.1} GB {}", p.index + 1, gib, p.name);
                self.sources.push(load(disk.clone(), Some(i), title));
            }
        }
    }

    fn open_image(&mut self) {
        if let Some(file) = rfd::FileDialog::new().set_title("Open an APFS disk image").pick_file() {
            let path = file.display().to_string();
            let title = file.file_name().map_or(path.clone(), |n| n.to_string_lossy().into_owned());
            self.sources.push(load(path, None, title));
        }
    }

    fn mount(&mut self, s: usize, v: usize) {
        let Some(letter) = mount::free_drive_letters().into_iter().next() else {
            self.status = "No free drive letter".into();
            return;
        };
        let src = &self.sources[s];
        let info = &src.volumes[v];
        let result =
            if info.read_only { self.mount_read_only(s, v, &letter) } else { self.mount_through_writer(s, v, &letter) };
        match result {
            Ok((session, rw)) => {
                self.status = format!(
                    "Mounted {} at {letter} ({})",
                    self.sources[s].volumes[v].name,
                    if rw { "read-write" } else { "read-only" }
                );
                self.active.push(Active { source: s, vol: v, letter, rw, session });
            }
            Err(e) => {
                // Don't keep the disk locked for writing by a mount that didn't happen.
                if !self.active.iter().any(|a| a.source == s) {
                    self.writers.remove(&s);
                }
                self.status = format!("Couldn't mount: {e}");
            }
        }
    }

    fn mount_through_writer(&mut self, s: usize, v: usize, letter: &str) -> std::io::Result<(Session, bool)> {
        let src = &self.sources[s];
        let w = match self.writers.get(&s) {
            Some(w) => w.clone(),
            None => {
                let w = Arc::new(Mutex::new(Writer::open(&src.path, src.partition)?));
                self.writers.insert(s, w.clone());
                w
            }
        };
        let rw = {
            let mut g = w.lock().map_err(|_| std::io::Error::other("writer crashed"))?;
            if g.is_locked(v) {
                g.unlock(v, &src.volumes[v].password)?;
            }
            g.read_only_reason(v).is_none()
        };
        let session = mount::start_session(vec![mount::through_writer(&w, v, letter)?])?;
        Ok((session, rw))
    }

    fn mount_read_only(&mut self, s: usize, v: usize, letter: &str) -> std::io::Result<(Session, bool)> {
        let src = &self.sources[s];
        let c = match src.partition {
            Some(n) => Container::open_partition(&src.path, n)?,
            None => Container::open(&src.path)?,
        };
        // shortcut: the mount borrows the container for 'static, so each read-only mount leaks one
        // container (a file handle and a few KB) until the app exits. Writable mounts don't.
        let c: &'static Container = Box::leak(Box::new(c));
        let mut vol = c.volumes()?.into_iter().nth(v).ok_or_else(|| std::io::Error::other("volume vanished"))?;
        if vol.is_locked() {
            vol.unlock(&src.volumes[v].password)?;
        }
        Ok((mount::start_session(vec![mount::read_only(c, vol, letter)?])?, false))
    }

    fn unmount(&mut self, i: usize) {
        let a = self.active.remove(i);
        let name = self.sources[a.source].volumes[a.vol].name.clone();
        self.status = match a.session.stop() {
            Ok(()) => format!("Unmounted {name}"),
            Err(e) => format!("Unmounted {name}, but saving the last changes failed: {e}"),
        };
        if !self.active.iter().any(|x| x.source == a.source) {
            self.writers.remove(&a.source);
        }
        self.refresh(a.source);
    }

    /// Reloads a container's volume list, keeping what the user typed or ticked.
    fn refresh(&mut self, s: usize) {
        let src = &self.sources[s];
        let fresh = load(src.path.clone(), src.partition, String::new());
        let mut vols = fresh.volumes;
        for (old, new) in src.volumes.iter().zip(vols.iter_mut()) {
            new.read_only = old.read_only || new.snapshots > 0;
            new.password = old.password.clone();
        }
        self.sources[s].volumes = vols;
        self.sources[s].error = fresh.error;
    }
}

/// Reads a container's volume list (read-only, so it works while a volume is mounted).
fn load(path: String, partition: Option<usize>, title: String) -> Source {
    let opened = match partition {
        Some(n) => Container::open_partition(&path, n),
        None => Container::open(&path),
    };
    let (volumes, error) = match opened.and_then(|c| {
        let bs = c.block_size;
        Ok(c.volumes()?
            .into_iter()
            .map(|v| {
                let sb = &v.superblock;
                let snapshots = u64::from_le_bytes(sb[216..224].try_into().unwrap());
                VolInfo {
                    name: v.name.clone(),
                    used: u64::from_le_bytes(sb[88..96].try_into().unwrap()) * bs,
                    encrypted: v.encrypted,
                    snapshots,
                    read_only: snapshots > 0,
                    password: String::new(),
                }
            })
            .collect::<Vec<_>>())
    }) {
        Ok(v) => (v, None),
        Err(e) => (vec![], Some(e.to_string())),
    };
    Source { path, partition, title, volumes, error }
}

fn human(bytes: u64) -> String {
    let gb = bytes as f64 / 1e9;
    if gb >= 1.0 { format!("{gb:.1} GB") } else { format!("{:.1} MB", bytes as f64 / 1e6) }
}

impl eframe::App for App {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        egui::CentralPanel::default().show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.heading("Mac (APFS) drives");
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui.button("Open disk image…").clicked() {
                        self.open_image();
                    }
                    if ui.button("Refresh").clicked() {
                        self.scan_disks();
                    }
                });
            });
            if !self.admin {
                ui.horizontal(|ui| {
                    ui.colored_label(
                        egui::Color32::from_rgb(200, 120, 0),
                        "Reading physical disks needs administrator rights.",
                    );
                    if ui.button("Restart as administrator").clicked() {
                        relaunch_as_admin();
                    }
                });
            }
            ui.separator();
            if self.sources.is_empty() {
                ui.label(if self.admin {
                    "No APFS drives found. Plug one in and press Refresh."
                } else {
                    "Open a disk image, or restart as administrator to see drives."
                });
            }
            let mut action = None;
            egui::ScrollArea::vertical().auto_shrink([false, true]).max_height(ui.available_height() - 30.0).show(
                ui,
                |ui| {
                    for (s, src) in self.sources.iter_mut().enumerate() {
                        ui.strong(&src.title);
                        if let Some(e) = &src.error {
                            ui.colored_label(egui::Color32::RED, e);
                        }
                        egui::Grid::new(("vols", s)).num_columns(5).striped(true).spacing([16.0, 6.0]).show(ui, |ui| {
                            for (v, info) in src.volumes.iter_mut().enumerate() {
                                ui.label(&info.name);
                                ui.label(human(info.used));
                                let mut notes = vec![];
                                if info.encrypted {
                                    notes.push("encrypted".to_string());
                                }
                                if info.snapshots > 0 {
                                    notes.push(format!("{} snapshots (read-only)", info.snapshots));
                                }
                                ui.label(notes.join(", "));
                                match self.active.iter().position(|a| a.source == s && a.vol == v) {
                                    Some(i) => {
                                        let a = &self.active[i];
                                        ui.label(format!(
                                            "{} ({})",
                                            a.letter,
                                            if a.rw { "read-write" } else { "read-only" }
                                        ));
                                        ui.horizontal(|ui| {
                                            if ui.button("Open").clicked() {
                                                let _ = std::process::Command::new("explorer.exe")
                                                    .arg(format!("{}\\", a.letter))
                                                    .spawn();
                                            }
                                            if ui.button("Unmount").clicked() {
                                                action = Some((false, i, 0));
                                            }
                                        });
                                    }
                                    None => {
                                        ui.horizontal(|ui| {
                                            if info.encrypted {
                                                ui.add(
                                                    egui::TextEdit::singleline(&mut info.password)
                                                        .password(true)
                                                        .hint_text("password")
                                                        .desired_width(110.0),
                                                );
                                            }
                                            ui.add_enabled(
                                                info.snapshots == 0,
                                                egui::Checkbox::new(&mut info.read_only, "Read-only"),
                                            );
                                        });
                                        if ui.button("Mount").clicked() {
                                            action = Some((true, s, v));
                                        }
                                    }
                                }
                                ui.end_row();
                            }
                        });
                        ui.add_space(10.0);
                    }
                },
            );
            match action {
                Some((true, s, v)) => self.mount(s, v),
                Some((false, i, _)) => self.unmount(i),
                None => {}
            }
            ui.separator();
            ui.label(&self.status);
        });
    }
}

impl Drop for App {
    fn drop(&mut self) {
        for a in self.active.drain(..) {
            let _ = a.session.stop();
        }
    }
}

#[link(name = "shell32")]
unsafe extern "system" {
    fn IsUserAnAdmin() -> i32;
    fn ShellExecuteW(
        hwnd: isize,
        op: *const u16,
        file: *const u16,
        params: *const u16,
        dir: *const u16,
        show: i32,
    ) -> isize;
}

fn is_admin() -> bool {
    // SAFETY: no arguments.
    unsafe { IsUserAnAdmin() != 0 }
}

fn relaunch_as_admin() {
    let wide = |s: &str| s.encode_utf16().chain([0]).collect::<Vec<u16>>();
    let Ok(exe) = std::env::current_exe() else { return };
    let (verb, file) = (wide("runas"), wide(&exe.display().to_string()));
    // SAFETY: NUL-terminated UTF-16 strings that outlive the call.
    let ok = unsafe { ShellExecuteW(0, verb.as_ptr(), file.as_ptr(), std::ptr::null(), std::ptr::null(), 1) } > 32;
    if ok {
        std::process::exit(0);
    }
}
