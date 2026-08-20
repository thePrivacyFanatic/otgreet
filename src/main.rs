use std::{
    cell::OnceCell,
    env,
    fs::{self, File, read_dir},
    io::{BufRead, BufReader},
    os::unix::net::UnixStream,
    path::{Path, PathBuf},
    process::Command,
};

use color_eyre::eyre::{Error, Result};
use crossterm::event::{Event, EventStream, KeyCode};

use greetd_ipc::{AuthMessageType, ErrorType, Request, Response, codec::SyncCodec};
use ratatui::{
    DefaultTerminal, Frame,
    layout::{
        Constraint::{Fill, Length, Min},
        Direction::{Horizontal, Vertical},
        Flex::{SpaceBetween, SpaceEvenly},
        Layout,
    },
    style::{Color, Modifier, Stylize},
    text::Span,
    widgets::{Block, Gauge, Padding, Paragraph},
};
use tokio::time::{Duration, Instant, sleep_until};
use tokio_stream::{self, StreamExt};
use totp_rs::Totp;

#[tokio::main]
async fn main() -> Result<()> {
    color_eyre::install()?;
    if let Some(arg) = env::args().nth(1) {
        match arg.as_str() {
            "init" => init(),
            _ => help(),
        }
    } else {
        let terminal = ratatui::init();
        let app_result = App::default().run(terminal).await;
        ratatui::restore();
        app_result
    }
}

fn init() -> Result<()> {
    match Totp::default().to_url() {
        Ok(url) => {
            fs::write("/etc/greetotp", &url)?;
            println!("generated url is: {}", url);
        }
        Err(err) => println!("generation failed with {}", Error::from(err)),
    }
    Ok(())
}

fn help() -> Result<()> {
    println!("otgreet [init]");
    println!("adding init creates the otp and prints the otpauth url");
    println!("anything else shows this help");
    Ok(())
}

struct TotpState {
    current: String,
    next: Instant,
    manager: OnceCell<Totp>,
}

impl Default for TotpState {
    fn default() -> Self {
        TotpState {
            current: "N/A".to_string(),
            next: Instant::now(),
            manager: OnceCell::new(),
        }
    }
}

impl TotpState {
    fn update(&mut self) {
        match self.manager.get() {
            Some(manager) => {
                self.current = manager.generate_current().to_string();
                self.next = Instant::now() + Duration::from_secs(manager.ttl());
            }
            None => self.next = Instant::now() + Duration::from_secs(1),
        }
    }
}

struct AuthQuestion {
    message_type: AuthMessageType,
    message: String,
}

#[derive(Default)]
enum AuthStatus {
    #[default]
    None,
    Question(AuthQuestion),
    Completed,
}

#[derive(Default)]
struct Auth {
    stream: OnceCell<UnixStream>,
    status: AuthStatus,
    answer: String,
    info: String,
}

impl Auth {
    fn connect(&mut self) -> Result<()> {
        let sock = env::var("GREETD_SOCK")?;
        drop(self.stream.set(UnixStream::connect(sock)?));
        Ok(())
    }

    fn register(&mut self, response: Response) -> Result<bool> {
        self.status = match response {
            Response::Success => AuthStatus::Completed,
            Response::AuthMessage {
                auth_message_type,
                auth_message,
            } => match auth_message_type {
                AuthMessageType::Info | AuthMessageType::Error => {
                    self.info = auth_message;
                    return self.register(match self.stream.get() {
                        Some(ref mut stream) => {
                            Request::PostAuthMessageResponse { response: None }.write_to(stream)?;
                            Response::read_from(stream)?
                        }
                        None => Response::AuthMessage {
                            auth_message_type: AuthMessageType::Secret,
                            auth_message: "placeholder after info message".to_string(),
                        },
                    });
                }
                AuthMessageType::Visible | AuthMessageType::Secret => {
                    AuthStatus::Question(AuthQuestion {
                        message_type: auth_message_type,
                        message: auth_message,
                    })
                }
            },
            Response::Error {
                error_type,
                description,
            } => {
                return match error_type {
                    ErrorType::AuthError => Ok(false),
                    ErrorType::Error => Err(Error::msg(description)),
                };
            }
        };
        self.answer.clear();
        Ok(true)
    }

    fn create_session(&mut self) -> Result<bool> {
        self.register(match self.stream.get() {
            Some(ref mut stream) => {
                Request::CreateSession {
                    username: self.answer.clone(),
                }
                .write_to(stream)?;
                Response::read_from(stream)?
            }
            None => Response::AuthMessage {
                auth_message_type: greetd_ipc::AuthMessageType::Secret,
                auth_message: "placeholder auth message".to_string(),
            },
        })
    }

    fn answer(&mut self) -> Result<bool> {
        self.register(match self.stream.get() {
            Some(ref mut stream) => {
                Request::PostAuthMessageResponse {
                    response: Some(self.answer.clone()),
                }
                .write_to(stream)?;
                Response::read_from(stream)?
            }
            None => {
                if self.answer == "123456" {
                    Response::Success
                } else {
                    Response::Error {
                        error_type: ErrorType::AuthError,
                        description: "wrong password".to_string(),
                    }
                }
            }
        })
    }

    fn cancel_session(&mut self) -> Result<()> {
        if let Some(ref mut stream) = self.stream.get() {
            Request::CancelSession.write_to(stream)?;
        }
        self.status = AuthStatus::None;
        Ok(())
    }

    fn start_session(&mut self, entry: &Path) -> Result<()> {
        if let Some(ref mut stream) = self.stream.get() {
            Request::StartSession {
                cmd: vec![getcmd(entry)?],
                env: vec![],
            }
            .write_to(stream)?;
        }
        Ok(())
    }

    fn poweroff() -> Result<()> {
        Command::new("/bin/loginctl").arg("poweroff").spawn()?;
        Ok(())
    }

    fn restart() -> Result<()> {
        Command::new("/bin/loginctl").arg("reboot").spawn()?;
        Ok(())
    }
}

#[derive(Default, PartialEq, Clone)]
enum Selected {
    #[default]
    Auth,
    Action,
}

#[derive(Default)]
enum Action {
    #[default]
    Poweroff,
    Restart,
    SwitchUser,
}

#[derive(Default)]
struct App {
    session: usize,
    auth: Auth,
    selected: Selected,
    action: Action,
    otp: TotpState,
    sessions: Vec<PathBuf>,
    wrong: bool,
    err: String,
}

impl App {
    const FRAMES_PER_SECOND: f32 = 60.0;

    /// the main app setup procedure and event loop
    async fn run(mut self, mut terminal: DefaultTerminal) -> Result<()> {
        let period = Duration::from_secs_f32(1.0 / Self::FRAMES_PER_SECOND);
        let mut interval = tokio::time::interval(period);
        let mut events = EventStream::new();
        self.get_sessions();
        let conn = self.auth.connect();
        drop(fs::read("/etc/greetotp").map(|bytes| {
            String::from_utf8(bytes)
                .map(|url| Totp::from_url(url).map(|otp| self.otp.manager.set(otp)))
        }));
        #[cfg(not(debug_assertions))]
        conn.expect("failed to connect to greetd!");
        drop(conn);

        while !matches!(self.auth.status, AuthStatus::Completed) {
            tokio::select! {
            _ = interval.tick() => { terminal.draw(|frame| self.render(frame))?; },
            Some(Ok(event)) = events.next() => self.handle_event(&event),
            _ = sleep_until(self.otp.next) => self.otp.update(),
            }
        }
        self.auth.start_session(&self.sessions[self.session])?;
        Ok(())
    }

    fn get_sessions(&mut self) {
        let searchpaths = ["/usr/share/xsessions", "/usr/share/wayland-sessions/"];

        searchpaths
            .iter()
            .filter_map(|searchpath| read_dir(searchpath).ok())
            .map(|rd| {
                rd.filter_map(|de| de.ok())
                    .filter(|entry| entry.file_type().is_ok_and(|ent| ent.is_file()))
            })
            .for_each(|dir| dir.for_each(|sessionpath| self.sessions.push(sessionpath.path())));
    }

    /// the function that renders the UI
    fn render(&self, frame: &mut Frame) {
        let row = Layout::default()
            .direction(Vertical)
            .constraints([Length(20)])
            .flex(ratatui::layout::Flex::Center)
            .split(frame.area())[0];

        let square = Layout::default()
            .direction(Horizontal)
            .constraints([Length(50)])
            .flex(ratatui::layout::Flex::Center)
            .split(row)[0];

        let rootblock = Block::bordered();

        let interfacelayout = Layout::default()
            .direction(Vertical)
            .constraints([Min(4), Min(11), Min(1)])
            .split(rootblock.inner(square));

        frame.render_widget(rootblock, square);

        let otpblock = Block::bordered().padding(Padding::horizontal(1));

        let otplayout = Layout::default()
            .direction(Vertical)
            .constraints([Min(1); 2])
            .flex(SpaceBetween)
            .split(otpblock.inner(interfacelayout[0]));

        frame.render_widget(otpblock, interfacelayout[0]);

        let otpdisp = Span::raw(&self.otp.current).into_centered_line();
        frame.render_widget(otpdisp, otplayout[0]);

        let time_left = self.otp.next.duration_since(Instant::now());

        let refresh = match self.otp.manager.get() {
            Some(totp) => Gauge::default()
                .label(format!("{}s", time_left.as_secs()))
                .ratio((totp.step() as f64 - time_left.as_secs_f64()) / totp.step() as f64),
            None => Gauge::default().label("no TOTP key found!").ratio(1.),
        };
        frame.render_widget(refresh, otplayout[1]);

        let loginblock = Block::bordered()
            .padding(Padding::horizontal(1))
            .border_style(if self.selected == Selected::Auth {
                Color::Yellow
            } else {
                Color::default()
            });

        let loginlayout = Layout::default()
            .direction(Vertical)
            .constraints([Min(3), Min(1), Min(2)])
            .flex(SpaceBetween)
            .split(loginblock.inner(interfacelayout[1]));

        frame.render_widget(loginblock, interfacelayout[1]);

        let (question_block, answer) = match &self.auth.status {
            AuthStatus::None => (
                Block::bordered()
                    .title("username")
                    .border_style(if self.wrong {
                        Color::Red
                    } else if self.selected == Selected::Auth {
                        Color::Yellow
                    } else {
                        Color::default()
                    }),
                &self.auth.answer,
            ),
            AuthStatus::Question(question) => (
                Block::bordered().title(&question.message as &str),
                match question.message_type {
                    AuthMessageType::Visible => &self.auth.answer,
                    AuthMessageType::Secret => &"*".repeat(self.auth.answer.chars().count()),
                    _ => &"oops, this does not belong here...".to_string(),
                },
            ),
            AuthStatus::Completed => (
                Block::bordered().border_style(Color::Green),
                &"starting session...".to_string(),
            ),
        };

        frame.render_widget(
            Paragraph::new(Span::raw(answer)).block(question_block),
            loginlayout[0],
        );

        frame.render_widget(Span::raw(&self.auth.info), loginlayout[1]);

        let sessionblock = Block::bordered()
            .title("session")
            .padding(Padding::horizontal(1));

        let session = self
            .sessions
            .get(self.session)
            .map_or("Error".to_string(), |file| {
                format!("{}", file.file_prefix().unwrap().display())
            });

        let sessionlayout = Layout::default()
            .direction(Horizontal)
            .constraints([Length(1), Fill(1), Length(1)])
            .flex(SpaceBetween)
            .split(sessionblock.inner(loginlayout[2]));

        frame.render_widget(sessionblock, loginlayout[2]);

        frame.render_widget(Span::raw("◀"), sessionlayout[0]);
        frame.render_widget(Span::raw(session).into_centered_line(), sessionlayout[1]);
        frame.render_widget(Span::raw("▶"), sessionlayout[2]);

        let actionblock = Block::bordered().border_style(if self.selected == Selected::Action {
            Color::Yellow
        } else {
            Color::default()
        });

        let actionlayout = Layout::default()
            .direction(Horizontal)
            .flex(SpaceEvenly)
            .constraints(if matches!(self.auth.status, AuthStatus::Question(_)) {
                vec![11, 10, 14]
            } else {
                vec![11, 10]
            })
            .split(actionblock.inner(interfacelayout[2]));

        frame.render_widget(actionblock, interfacelayout[2]);

        let mut poweroff = Span::raw("(P)ower off");
        let mut restart = Span::raw("(R)estart");
        let mut switch_user = Span::raw("(S)witch user");

        if self.selected == Selected::Action {
            match self.action {
                Action::Poweroff => poweroff = poweroff.add_modifier(Modifier::REVERSED),
                Action::Restart => restart = restart.add_modifier(Modifier::REVERSED),
                Action::SwitchUser => switch_user = switch_user.add_modifier(Modifier::REVERSED),
            }
        }

        frame.render_widget(poweroff, actionlayout[0]);
        frame.render_widget(restart, actionlayout[1]);
        if matches!(self.auth.status, AuthStatus::Question(_)) {
            frame.render_widget(switch_user, actionlayout[2]);
        }
    }

    fn handle_event(&mut self, event: &Event) {
        if let Some(key) = event.as_key_press_event() {
            match key.code {
                KeyCode::Esc => match self.selected {
                    Selected::Auth => self.selected = Selected::Action,
                    Selected::Action => self.selected = Selected::Auth,
                },
                KeyCode::Down => {
                    if self.selected == Selected::Auth {
                        self.selected = Selected::Action
                    }
                }
                KeyCode::Up => {
                    if self.selected == Selected::Action {
                        self.selected = Selected::Auth
                    }
                }
                KeyCode::Right => match self.selected {
                    Selected::Auth => {
                        if self.session < self.sessions.len() - 1 {
                            self.session += 1
                        }
                    }
                    Selected::Action => {
                        self.action = match self.action {
                            Action::Poweroff => Action::Restart,
                            Action::Restart | Action::SwitchUser => {
                                if matches!(self.auth.status, AuthStatus::Question(_)) {
                                    Action::SwitchUser
                                } else {
                                    Action::Restart
                                }
                            }
                        }
                    }
                },
                KeyCode::Left => match self.selected {
                    Selected::Auth => {
                        if self.session > 0 {
                            self.session -= 1
                        }
                    }
                    Selected::Action => {
                        self.action = match self.action {
                            Action::Poweroff | Action::Restart => Action::Poweroff,
                            Action::SwitchUser => Action::Restart,
                        }
                    }
                },
                KeyCode::Enter => match self.selected {
                    Selected::Auth => {
                        self.wrong = match self.auth.status {
                            AuthStatus::None => self.auth.create_session().unwrap(),
                            AuthStatus::Question(_) => self.auth.answer().unwrap(),
                            AuthStatus::Completed => false,
                        }
                    }
                    Selected::Action => match self.action {
                        Action::Poweroff => Auth::poweroff(),
                        Action::Restart => Auth::restart(),
                        Action::SwitchUser => self.auth.cancel_session(),
                    }
                    .unwrap_or_else(|err| self.err = err.to_string()),
                },
                KeyCode::Char(char) => match self.selected {
                    Selected::Auth => self.auth.answer.push(char),
                    Selected::Action => match char {
                        'p' | 'P' => drop(Auth::poweroff()),
                        'r' | 'R' => drop(Auth::restart()),
                        's' | 'S' => {
                            if matches!(self.auth.status, AuthStatus::Question(_)) {
                                drop(self.auth.cancel_session());
                            }
                        }
                        _ => {}
                    },
                },
                KeyCode::Backspace => match self.selected {
                    Selected::Auth => drop(self.auth.answer.pop()),
                    Selected::Action => self.selected = Selected::Auth,
                },
                _ => {}
            }
        }
    }
}

fn getcmd(path: &Path) -> Result<String> {
    let reader = BufReader::new(File::open(path)?);
    for line in reader.lines() {
        let l = line?;
        if l.starts_with("Exec=") {
            return Ok(l.trim_start_matches("Exec=").to_string());
        }
    }
    Err(Error::msg("No exec clause in .desktop file"))
}
