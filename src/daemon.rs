//! The dumbpipe daemon.
//!
//! The daemon runs many named tunnels over a single iroh endpoint, driven by a
//! TOML config file. It is the multi-tunnel counterpart to the single-purpose
//! `listen-tcp` / `connect-tcp` subcommands.
//!
//! A `[[connect]]` entry binds a local TCP port and forwards every accepted
//! socket to a remote endpoint under a name. A `[[accept]]` entry forwards
//! incoming named streams to a local TCP backend selected by that name. Because
//! one endpoint serves several tunnels, each stream is prefixed with a [`Header`]
//! carrying the name and an optional token.
//!
//! The daemon speaks its own ALPN ([`DAEMON_ALPN`]), distinct from the
//! single-tunnel dumbpipe protocol.

use std::{
    collections::HashMap,
    ffi::OsString,
    path::{Path, PathBuf},
    str::FromStr,
    sync::Arc,
    time::Duration,
};

use arc_swap::ArcSwap;
use clap::{Parser, Subcommand};
use dumbpipe::EndpointTicket;
use iroh::{address_lookup::MemoryLookup, EndpointAddr, EndpointId, SecretKey};
use iroh_util::connection_pool::{ConnectionPool, ConnectionRef, Options};
use n0_error::{bail_any, ensure_any, Result, StdResultExt};
use notify::Watcher;
use serde::{Deserialize, Serialize};
use service_manager::{
    RestartPolicy, ServiceInstallCtx, ServiceLabel, ServiceLevel, ServiceManager, ServiceStartCtx,
    ServiceStatus, ServiceStatusCtx, ServiceStopCtx, ServiceUninstallCtx,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    select,
    sync::mpsc,
    time::timeout,
};
use tokio_util::{sync::CancellationToken, task::AbortOnDropHandle};
use tracing::{debug, info, info_span, warn, Instrument};

use crate::CommonArgs;

/// The ALPN spoken by the daemon protocol.
///
/// Distinct from [`dumbpipe::ALPN`] so a daemon and a plain `dumbpipe connect`
/// never accidentally talk to each other; the daemon also frames every stream
/// with a [`Header`] rather than the fixed handshake.
const DAEMON_ALPN: &[u8] = b"DUMBPIPEDAEMON0";

/// The maximum size of an encoded [`Header`], in bytes.
///
/// The accepting side reads the header length from the wire before allocating,
/// so this bounds the allocation a peer can request.
const MAX_HEADER_LEN: usize = 4096;

/// The number of random bytes in a `--secure` token, before base32 encoding.
const SECURE_TOKEN_BYTES: usize = 16;

/// How long the connection pool keeps an idle connection before closing it.
///
/// Connect tunnels reuse one iroh connection per remote across many TCP
/// streams; this keeps the connection warm between bursts of streams.
const POOL_IDLE_TIMEOUT: Duration = Duration::from_secs(30);

/// How long the connection pool waits for a connect to complete.
///
/// Connecting by endpoint id alone goes through discovery and a relay, so this
/// is generous compared to the pool's one-second default.
const POOL_CONNECT_TIMEOUT: Duration = Duration::from_secs(15);

/// How long to wait after a config change before reloading, to coalesce the
/// burst of filesystem events a single save produces.
const RELOAD_DEBOUNCE: Duration = Duration::from_millis(200);

/// The label identifying the daemon service to the platform service manager.
///
/// A single-component label keeps the systemd unit named `dumbpipe.service`
/// rather than the `{organization}-{application}` form a qualified label yields.
const SERVICE_LABEL: &str = "dumbpipe";

/// Arguments for the `daemon` subcommand.
#[derive(Parser, Debug)]
#[command(arg_required_else_help = true)]
pub struct DaemonArgs {
    #[clap(subcommand)]
    pub command: DaemonCommand,

    /// Path to the daemon config file.
    ///
    /// Defaults to `<data_dir>/dumbpipe/daemon/daemon.toml`, where `data_dir`
    /// is the platform data directory (see the `dirs` crate).
    #[clap(short = 'c', long, global = true)]
    pub config: Option<PathBuf>,

    #[clap(flatten)]
    pub common: CommonArgs,
}

/// The daemon subcommands.
#[derive(Subcommand, Debug)]
pub enum DaemonCommand {
    /// Install the daemon as a user-level service.
    Install,

    /// Stop and remove the daemon service.
    Uninstall,

    /// Start the installed daemon service.
    Start,

    /// Stop the running daemon service.
    Stop,

    /// Show the daemon service status.
    Status,

    /// Run the daemon in the foreground.
    Run,

    /// Add an accept tunnel to the config file.
    Accept(AcceptCmd),

    /// Add a connect tunnel to the config file.
    Connect(ConnectCmd),

    /// Print the configured connect and accept tunnels.
    Show,
}

/// Arguments for `daemon accept`.
#[derive(Parser, Debug)]
pub struct AcceptCmd {
    /// The name that selects this backend.
    pub name: String,

    /// The local TCP backend address to forward matching streams to.
    pub addr: String,

    /// Require this token from the connecting side.
    #[clap(long)]
    pub token: Option<String>,

    /// Generate a random token (16 base32 bytes) instead of passing one.
    #[clap(long)]
    pub secure: bool,
}

/// Arguments for `daemon connect`.
#[derive(Parser, Debug)]
pub struct ConnectCmd {
    /// The remote and name, written as `remote:name`.
    ///
    /// `remote` is an endpoint id or ticket; `name` selects the accept tunnel
    /// on the remote daemon.
    pub remote_name: String,

    /// The local TCP address to listen on.
    pub addr: String,

    /// Token required by the remote accept tunnel, if any.
    #[clap(long)]
    pub token: Option<String>,
}

/// The daemon config, parsed from and written to TOML.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Config {
    /// Whether to watch the config file and apply changes while running.
    #[serde(default = "default_true")]
    reload: bool,
    /// Outgoing tunnels: local TCP port -> remote endpoint, under a name.
    #[serde(default)]
    connect: Vec<ConnectConfig>,
    /// Incoming tunnels: named stream -> local TCP backend.
    #[serde(default)]
    accept: Vec<AcceptConfig>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            reload: true,
            connect: Vec::new(),
            accept: Vec::new(),
        }
    }
}

fn default_true() -> bool {
    true
}

/// A single `[[connect]]` entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ConnectConfig {
    /// The remote endpoint id or ticket to forward to.
    remote: String,
    /// The name sent in the header, used by the remote to route the stream.
    name: String,
    /// The local TCP address to listen on.
    addr: String,
    /// Token to present to the remote accept tunnel, if it requires one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    token: Option<String>,
}

/// A single `[[accept]]` entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct AcceptConfig {
    /// The name that selects this backend.
    name: String,
    /// The local TCP backend to forward matching streams to.
    addr: String,
    /// Token the connecting side must present, if set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    token: Option<String>,
}

/// The per-stream header, postcard-encoded ahead of any forwarded data.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct Header {
    /// The tunnel name, used by the accepting daemon to route the stream.
    name: String,
    /// The token to authorize the stream, if the connect side has one.
    #[serde(default)]
    token: Option<String>,
}

/// A resolved accept route: where to forward and the token it requires.
#[derive(Debug, Clone)]
struct AcceptRoute {
    addr: String,
    token: Option<String>,
}

/// Accept routes, keyed by name. Swapped atomically on reload.
type Routes = HashMap<String, AcceptRoute>;

/// A running connect tunnel. Dropping it aborts the listener task.
struct ConnectTunnel {
    config: ConnectConfig,
    _handle: AbortOnDropHandle<()>,
}

/// Dispatches the `daemon` subcommand.
pub(crate) async fn run(args: DaemonArgs) -> Result<()> {
    let config_path = match args.config {
        Some(path) => path,
        None => daemon_dir()?.join("daemon.toml"),
    };
    match args.command {
        DaemonCommand::Install => cmd_install(&config_path),
        DaemonCommand::Uninstall => cmd_uninstall(),
        DaemonCommand::Start => cmd_service_start(),
        DaemonCommand::Stop => cmd_service_stop(),
        DaemonCommand::Status => cmd_service_status(),
        DaemonCommand::Run => run_foreground(config_path, args.common).await,
        DaemonCommand::Accept(cmd) => cmd_accept(&config_path, cmd),
        DaemonCommand::Connect(cmd) => cmd_connect(&config_path, cmd),
        DaemonCommand::Show => cmd_show(&config_path),
    }
}

/// Builds the platform service manager, set to manage user-level services.
fn service_manager() -> Result<Box<dyn ServiceManager>> {
    let mut manager =
        <dyn ServiceManager>::native().std_context("no supported service manager found")?;
    manager
        .set_level(ServiceLevel::User)
        .std_context("user-level services are not supported on this platform")?;
    Ok(manager)
}

/// The service label for the daemon.
fn service_label() -> ServiceLabel {
    SERVICE_LABEL.parse().expect("service label is valid")
}

/// Installs the daemon as a user-level service that runs `daemon run`.
fn cmd_install(config_path: &Path) -> Result<()> {
    let manager = service_manager()?;
    let label = service_label();
    let program =
        std::env::current_exe().std_context("could not determine the dumbpipe binary path")?;
    // Pass an absolute config path so the service finds it regardless of the
    // working directory it is launched in.
    let config = std::path::absolute(config_path)
        .with_std_context(|_| format!("could not resolve config path {}", config_path.display()))?;
    let result = manager.install(ServiceInstallCtx {
        label: label.clone(),
        program,
        args: vec![
            OsString::from("daemon"),
            OsString::from("run"),
            OsString::from("-c"),
            config.clone().into_os_string(),
        ],
        contents: None,
        username: None,
        working_directory: None,
        environment: None,
        autostart: true,
        restart_policy: RestartPolicy::default(),
    });
    if result.is_err() && cfg!(target_os = "macos") {
        // A user-level launchd agent only loads in a GUI login session, which an
        // SSH session lacks. No elevated permissions are needed.
        eprintln!(
            "note: a user service uses launchd, which only loads agents in a GUI \
             login session that an SSH session does not have. Run `dumbpipe daemon \
             install` from a Terminal in the desktop session; sudo is not required."
        );
    }
    result.std_context("failed to install service")?;
    println!("installed dumbpipe daemon service {label}");
    println!("config: {}", config.display());
    println!("start it with: dumbpipe daemon start");
    Ok(())
}

/// Stops and removes the daemon service.
fn cmd_uninstall() -> Result<()> {
    let manager = service_manager()?;
    let label = service_label();
    manager
        .uninstall(ServiceUninstallCtx {
            label: label.clone(),
        })
        .std_context("failed to uninstall service")?;
    println!("uninstalled dumbpipe daemon service {label}");
    Ok(())
}

/// Starts the installed daemon service.
fn cmd_service_start() -> Result<()> {
    let manager = service_manager()?;
    let label = service_label();
    manager
        .start(ServiceStartCtx {
            label: label.clone(),
        })
        .std_context("failed to start service")?;
    println!("started dumbpipe daemon service {label}");
    Ok(())
}

/// Stops the running daemon service.
fn cmd_service_stop() -> Result<()> {
    let manager = service_manager()?;
    let label = service_label();
    manager
        .stop(ServiceStopCtx {
            label: label.clone(),
        })
        .std_context("failed to stop service")?;
    println!("stopped dumbpipe daemon service {label}");
    Ok(())
}

/// Prints the daemon service status.
fn cmd_service_status() -> Result<()> {
    let manager = service_manager()?;
    let label = service_label();
    let status = manager
        .status(ServiceStatusCtx { label })
        .std_context("failed to query service status")?;
    match status {
        ServiceStatus::NotInstalled => println!("not installed"),
        ServiceStatus::Running => println!("running"),
        ServiceStatus::Stopped(Some(reason)) => println!("stopped: {reason}"),
        ServiceStatus::Stopped(None) => println!("stopped"),
    }
    Ok(())
}

/// Prints the configured connect and accept tunnels.
fn cmd_show(config_path: &Path) -> Result<()> {
    let config = load_or_default_config(config_path)?;
    print_tunnels(&config);
    Ok(())
}

/// Prints one line per configured connect and accept tunnel.
///
/// Used both by `daemon show` and at startup, so the running set matches what
/// `show` reports. A `[token]` marker flags a token-protected tunnel.
fn print_tunnels(config: &Config) {
    for connect in &config.connect {
        let token = if connect.token.is_some() {
            " [token]"
        } else {
            ""
        };
        println!(
            "connect {} -> {}:{}{}",
            connect.addr, connect.remote, connect.name, token
        );
    }
    for accept in &config.accept {
        let token = if accept.token.is_some() {
            " [token]"
        } else {
            ""
        };
        println!("accept {} -> {}{}", accept.name, accept.addr, token);
    }
}

/// Adds an `[[accept]]` entry to the config file.
fn cmd_accept(config_path: &Path, cmd: AcceptCmd) -> Result<()> {
    let token = match (cmd.secure, cmd.token) {
        (true, Some(_)) => bail_any!("--secure and --token are mutually exclusive"),
        (true, None) => Some(generate_token()),
        (false, token) => token,
    };
    let mut config = load_or_default_config(config_path)?;
    ensure_any!(
        !config.accept.iter().any(|a| a.name == cmd.name),
        "an accept entry named {:?} already exists",
        cmd.name
    );
    config.accept.push(AcceptConfig {
        name: cmd.name.clone(),
        addr: cmd.addr.clone(),
        token: token.clone(),
    });
    write_config(config_path, &config)?;
    println!("added accept {} -> {}", cmd.name, cmd.addr);
    if let Some(token) = &token {
        println!("token: {token}");
    }
    Ok(())
}

/// Adds a `[[connect]]` entry to the config file.
fn cmd_connect(config_path: &Path, cmd: ConnectCmd) -> Result<()> {
    let Some((remote, name)) = cmd.remote_name.split_once(':') else {
        bail_any!("expected remote:name, got {:?}", cmd.remote_name);
    };
    ensure_any!(
        !remote.is_empty() && !name.is_empty(),
        "expected remote:name with both parts present, got {:?}",
        cmd.remote_name
    );
    // Validate the remote up front so a typo is caught now, not at next start.
    parse_remote(remote)?;
    let mut config = load_or_default_config(config_path)?;
    config.connect.push(ConnectConfig {
        remote: remote.to_string(),
        name: name.to_string(),
        addr: cmd.addr.clone(),
        token: cmd.token,
    });
    write_config(config_path, &config)?;
    println!("added connect {remote}:{name} -> {}", cmd.addr);
    Ok(())
}

/// Runs the daemon in the foreground until interrupted with ctrl-c.
async fn run_foreground(config_path: PathBuf, common: CommonArgs) -> Result<()> {
    let dir = daemon_dir()?;
    // Create an empty config rather than failing when none exists yet.
    if !config_path.exists() {
        write_config(&config_path, &Config::default())?;
        info!(path = %config_path.display(), "created config file");
    }
    let config = load_config(&config_path)?;
    let secret_key = load_or_create_secret(&dir)?;

    // Keep the memory lookup so reloads can register hints for new remotes.
    let memory_lookup = MemoryLookup::new();
    seed_lookup(&memory_lookup, &config.connect);

    // The daemon always speaks DAEMON_ALPN with a postcard header, so it ignores
    // `--custom-alpn`. It still honors the bind-address options.
    let endpoint = crate::create_endpoint(
        secret_key,
        &common,
        vec![DAEMON_ALPN.to_vec()],
        Some(memory_lookup.clone()),
    )
    .await?;
    info!(endpoint_id = %endpoint.id(), "daemon endpoint bound");

    if timeout(crate::ONLINE_TIMEOUT, endpoint.online())
        .await
        .is_err()
    {
        warn!("failed to connect to the home relay");
    }

    println!("short addr: {}", endpoint.id());
    println!(" long addr: {}", EndpointTicket::new(endpoint.addr()));
    print_tunnels(&config);

    let pool = ConnectionPool::new(
        endpoint.clone(),
        DAEMON_ALPN,
        Options {
            idle_timeout: POOL_IDLE_TIMEOUT,
            connect_timeout: POOL_CONNECT_TIMEOUT,
            ..Default::default()
        },
    );

    // Accept routes live behind an ArcSwap so the accept loop and its per-stream
    // handlers always read the current routes; reload swaps in a new map.
    let routes = Arc::new(ArcSwap::from_pointee(build_routes(&config.accept)));
    let cancel = CancellationToken::new();
    let _accept = AbortOnDropHandle::new(tokio::spawn(run_accept(
        endpoint.clone(),
        routes.clone(),
        cancel.child_token(),
    )));

    // Connect tunnels are keyed by local addr and reconciled on reload.
    let mut connects: HashMap<String, ConnectTunnel> = HashMap::new();
    reconcile_connects(&mut connects, &config.connect, &pool).await;

    // Watch the config file when reload is enabled.
    let (mut reloads, _watcher) = if config.reload {
        let (tx, rx) = mpsc::unbounded_channel();
        let watcher = watch_config(&config_path, tx)?;
        info!(path = %config_path.display(), "watching config for changes");
        (Some(rx), Some(watcher))
    } else {
        (None, None)
    };

    loop {
        select! {
            _ = tokio::signal::ctrl_c() => {
                info!("got ctrl-c, shutting down");
                break;
            }
            Some(()) = maybe_recv(&mut reloads) => {
                // Coalesce the burst of events a single save produces.
                tokio::time::sleep(RELOAD_DEBOUNCE).await;
                if let Some(rx) = reloads.as_mut() {
                    while rx.try_recv().is_ok() {}
                }
                match load_config(&config_path) {
                    Ok(config) => {
                        routes.store(Arc::new(build_routes(&config.accept)));
                        seed_lookup(&memory_lookup, &config.connect);
                        reconcile_connects(&mut connects, &config.connect, &pool).await;
                        info!("reloaded config");
                    }
                    Err(cause) => warn!("failed to reload config: {cause}"),
                }
            }
        }
    }

    cancel.cancel();
    endpoint.close().await;
    Ok(())
}

/// Generates a random token: [`SECURE_TOKEN_BYTES`] random bytes, base32 encoded.
fn generate_token() -> String {
    let bytes: [u8; SECURE_TOKEN_BYTES] = rand::random();
    data_encoding::BASE32_NOPAD.encode(&bytes)
}

/// Builds the accept routes from the config, keyed by name.
fn build_routes(accept: &[AcceptConfig]) -> Routes {
    let mut routes = Routes::new();
    for entry in accept {
        let route = AcceptRoute {
            addr: entry.addr.clone(),
            token: entry.token.clone(),
        };
        if routes.insert(entry.name.clone(), route).is_some() {
            warn!(name = %entry.name, "duplicate accept name, later entry overrides");
        }
    }
    routes
}

/// Registers relay and address hints from the connect remotes that carry them.
///
/// Bare-id remotes carry no hints and are left to discovery. Unparseable
/// remotes are logged and skipped so one bad entry does not stop the rest.
fn seed_lookup(lookup: &MemoryLookup, connect: &[ConnectConfig]) {
    for entry in connect {
        match parse_remote(&entry.remote) {
            Ok(addr) if !addr.is_empty() => lookup.add_endpoint_info(addr),
            Ok(_) => {}
            Err(cause) => warn!(remote = %entry.remote, "invalid remote, skipping: {cause}"),
        }
    }
}

/// Reconciles the running connect tunnels with the desired config.
///
/// Tunnels are keyed by local addr. Tunnels whose addr is gone or whose config
/// changed are stopped; newly desired tunnels are bound and started. A bind
/// failure logs and skips that tunnel rather than stopping the daemon.
async fn reconcile_connects(
    connects: &mut HashMap<String, ConnectTunnel>,
    desired: &[ConnectConfig],
    pool: &ConnectionPool,
) {
    let mut want: HashMap<&str, &ConnectConfig> = HashMap::new();
    for entry in desired {
        if want.insert(entry.addr.as_str(), entry).is_some() {
            warn!(addr = %entry.addr, "duplicate connect addr, ignoring later entry");
        }
    }

    connects.retain(|addr, tunnel| match want.get(addr.as_str()) {
        Some(config) if **config == tunnel.config => true,
        _ => {
            info!(%addr, "stopping connect tunnel");
            false
        }
    });

    for (addr, config) in want {
        if connects.contains_key(addr) {
            continue;
        }
        match start_connect_tunnel(config.clone(), pool.clone()).await {
            Ok(tunnel) => {
                connects.insert(addr.to_string(), tunnel);
            }
            Err(cause) => warn!(%addr, "failed to start connect tunnel: {cause}"),
        }
    }
}

/// Binds a connect tunnel's local listener and spawns its accept loop.
async fn start_connect_tunnel(
    config: ConnectConfig,
    pool: ConnectionPool,
) -> Result<ConnectTunnel> {
    let remote = parse_remote(&config.remote)?;
    let listener = TcpListener::bind(&config.addr)
        .await
        .with_std_context(|_| format!("failed to bind {}", config.addr))?;
    info!(addr = %config.addr, remote = %remote.id, name = %config.name, "connect listening");
    let task_config = config.clone();
    let handle = tokio::spawn(async move {
        if let Err(cause) = run_connect(pool, listener, remote.id, task_config).await {
            warn!("connect tunnel stopped: {cause}");
        }
    });
    Ok(ConnectTunnel {
        config,
        _handle: AbortOnDropHandle::new(handle),
    })
}

/// Listens on a local TCP port and forwards each socket to the remote endpoint.
///
/// Runs in an `outgoing{remote}` span; each forwarded socket gets a child
/// `tcp{name, target}` span.
async fn run_connect(
    pool: ConnectionPool,
    listener: TcpListener,
    remote_id: EndpointId,
    config: ConnectConfig,
) -> Result<()> {
    let name = Arc::new(config.name);
    let token = Arc::new(config.token);
    async {
        loop {
            let (tcp_stream, peer) = listener
                .accept()
                .await
                .std_context("error accepting tcp connection")?;
            let pool = pool.clone();
            let name = name.clone();
            let token = token.clone();
            let span = info_span!("tcp", name = %name, target = %peer);
            tokio::spawn(
                async move {
                    let header = Header {
                        name: name.as_str().to_string(),
                        token: (*token).clone(),
                    };
                    if let Err(cause) = handle_connect(&pool, remote_id, header, tcp_stream).await {
                        warn!("error forwarding tcp connection: {cause}");
                    }
                }
                .instrument(span),
            );
        }
    }
    .instrument(info_span!("outgoing", remote = %remote_id.fmt_short()))
    .await
}

/// Forwards a single accepted TCP socket to the remote endpoint.
///
/// The iroh connection comes from the shared pool, so concurrent and successive
/// streams to the same remote reuse one connection. The [`ConnectionRef`] is
/// held until forwarding finishes, which keeps the pool from closing the
/// connection while it is in use.
async fn handle_connect(
    pool: &ConnectionPool,
    remote_id: EndpointId,
    header: Header,
    tcp_stream: TcpStream,
) -> Result<()> {
    let (tcp_recv, tcp_send) = tcp_stream.into_split();
    let connection = get_connection(pool, remote_id).await?;
    let (mut endpoint_send, endpoint_recv) = connection
        .open_bi()
        .await
        .std_context("error opening bidi stream")?;
    write_header(&mut endpoint_send, &header).await?;
    info!("connected");
    let result = crate::forward_bidi(tcp_recv, tcp_send, endpoint_recv, endpoint_send).await;
    info!("disconnected");
    result
}

/// Gets a pooled connection to `remote_id`, retrying the connect once on error.
///
/// The pool reuses a live connection if it has one. On a connect failure it
/// retries a single time, which covers a transient discovery or relay hiccup
/// and a connection that was evicted just as it was requested.
async fn get_connection(pool: &ConnectionPool, remote_id: EndpointId) -> Result<ConnectionRef> {
    match pool.get_or_connect(remote_id).await {
        Ok(connection) => Ok(connection),
        Err(cause) => {
            warn!(remote = %remote_id, "connect failed, retrying once: {cause}");
            pool.get_or_connect(remote_id)
                .await
                .with_std_context(|_| format!("error connecting to {remote_id}"))
        }
    }
}

/// Accepts incoming endpoint connections and routes their streams by name.
async fn run_accept(
    endpoint: iroh::Endpoint,
    routes: Arc<ArcSwap<Routes>>,
    token: CancellationToken,
) {
    loop {
        let incoming = select! {
            incoming = endpoint.accept() => incoming,
            _ = token.cancelled() => break,
        };
        let Some(incoming) = incoming else {
            break;
        };
        let Ok(accepting) = incoming.accept() else {
            continue;
        };
        let routes = routes.clone();
        tokio::spawn(async move {
            if let Err(cause) = handle_connection(accepting, routes).await {
                warn!("error handling incoming connection: {cause}");
            }
        });
    }
}

/// Accepts every bidi stream on one incoming connection and routes each by name.
///
/// A connecting daemon reuses one connection for many TCP streams, so each
/// stream arrives as a separate bidi stream that must be accepted in turn. Runs
/// in an `incoming{remote}` span; each forwarded stream gets a child
/// `tcp{name, target}` span.
async fn handle_connection(
    accepting: iroh::endpoint::Accepting,
    routes: Arc<ArcSwap<Routes>>,
) -> Result<()> {
    let connection = accepting.await.std_context("error accepting connection")?;
    let remote_id = connection.remote_id();
    async {
        loop {
            let (send, recv) = match connection.accept_bi().await {
                Ok(stream) => stream,
                // The remote closing the connection ends the stream loop normally.
                Err(cause) => {
                    debug!("accept_bi ended: {cause}");
                    break;
                }
            };
            let routes = routes.clone();
            tokio::spawn(
                async move {
                    if let Err(cause) = handle_stream(send, recv, &routes).await {
                        warn!("error handling stream: {cause}");
                    }
                }
                .in_current_span(),
            );
        }
        Ok(())
    }
    .instrument(info_span!("incoming", remote = %remote_id.fmt_short()))
    .await
}

/// Reads the header from one incoming stream, checks its token, and forwards it.
///
/// Runs in the incoming connection's span; the forwarded stream gets a child
/// `tcp{name, target}` span.
async fn handle_stream(
    send: noq::SendStream,
    mut recv: noq::RecvStream,
    routes: &ArcSwap<Routes>,
) -> Result<()> {
    let header = read_header(&mut recv).await?;
    let route = routes.load().get(&header.name).cloned();
    let Some(route) = route else {
        warn!(name = %header.name, "no route for name, dropping stream");
        return Ok(());
    };
    if let Some(expected) = &route.token {
        if header.token.as_deref() != Some(expected.as_str()) {
            warn!(name = %header.name, "token mismatch, dropping stream");
            return Ok(());
        }
    }
    let span = info_span!("tcp", name = %header.name, target = %route.addr);
    async move {
        let backend = TcpStream::connect(&route.addr)
            .await
            .with_std_context(|_| format!("error connecting to backend {}", route.addr))?;
        info!("connected");
        let (backend_recv, backend_send) = backend.into_split();
        let result = crate::forward_bidi(backend_recv, backend_send, recv, send).await;
        info!("disconnected");
        result
    }
    .instrument(span)
    .await
}

/// Writes the postcard-encoded header, length-prefixed with a big-endian `u32`.
async fn write_header<W: AsyncWrite + Unpin>(send: &mut W, header: &Header) -> Result<()> {
    let bytes = postcard::to_stdvec(header).std_context("failed to encode header")?;
    ensure_any!(
        bytes.len() <= MAX_HEADER_LEN,
        "header too large: {} bytes",
        bytes.len()
    );
    let len = bytes.len() as u32;
    send.write_all(&len.to_be_bytes()).await.anyerr()?;
    send.write_all(&bytes).await.anyerr()?;
    Ok(())
}

/// Reads a header written by [`write_header`].
async fn read_header<R: AsyncRead + Unpin>(recv: &mut R) -> Result<Header> {
    let mut len_buf = [0u8; 4];
    recv.read_exact(&mut len_buf).await.anyerr()?;
    let len = u32::from_be_bytes(len_buf) as usize;
    ensure_any!(len <= MAX_HEADER_LEN, "header too large: {len} bytes");
    let mut bytes = vec![0u8; len];
    recv.read_exact(&mut bytes).await.anyerr()?;
    postcard::from_bytes(&bytes).std_context("failed to decode header")
}

/// Parses a remote from an endpoint id (hex or base32) or a full ticket.
fn parse_remote(s: &str) -> Result<EndpointAddr> {
    // A ticket is the more specific form, so try it first and fall back to a
    // bare endpoint id.
    if let Ok(ticket) = EndpointTicket::from_str(s) {
        return Ok(ticket.endpoint_addr().clone());
    }
    let id = EndpointId::from_str(s).std_context("invalid remote endpoint id or ticket")?;
    Ok(EndpointAddr::from(id))
}

/// Returns the daemon data directory, `<data_dir>/dumbpipe/daemon`.
fn daemon_dir() -> Result<PathBuf> {
    let Some(data_dir) = dirs::data_dir() else {
        bail_any!("could not determine the platform data directory");
    };
    Ok(data_dir.join("dumbpipe").join("daemon"))
}

/// Loads and parses the config file at `path`, failing if it does not exist.
fn load_config(path: &Path) -> Result<Config> {
    let contents = std::fs::read_to_string(path)
        .with_std_context(|_| format!("failed to read config {}", path.display()))?;
    toml::from_str(&contents)
        .with_std_context(|_| format!("failed to parse config {}", path.display()))
}

/// Loads the config at `path`, returning the default config if it is missing.
fn load_or_default_config(path: &Path) -> Result<Config> {
    match std::fs::read_to_string(path) {
        Ok(contents) => toml::from_str(&contents)
            .with_std_context(|_| format!("failed to parse config {}", path.display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Config::default()),
        Err(e) => Err(e).with_std_context(|_| format!("failed to read config {}", path.display())),
    }
}

/// Writes the config to `path` as TOML, creating the parent directory if needed.
fn write_config(path: &Path, config: &Config) -> Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)
                .with_std_context(|_| format!("failed to create {}", parent.display()))?;
        }
    }
    let contents = toml::to_string(config).std_context("failed to serialize config")?;
    std::fs::write(path, contents)
        .with_std_context(|_| format!("failed to write {}", path.display()))?;
    Ok(())
}

/// Watches the config file and signals on `tx` when it changes.
///
/// Watches the parent directory rather than the file, so the watch survives
/// editors that replace the file on save. Events are filtered to the config
/// file's name.
fn watch_config(
    config_path: &Path,
    tx: mpsc::UnboundedSender<()>,
) -> Result<notify::RecommendedWatcher> {
    let dir = config_path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .map_or_else(|| PathBuf::from("."), Path::to_path_buf);
    let file_name = config_path.file_name().map(ToOwned::to_owned);
    let mut watcher = notify::recommended_watcher(move |res: notify::Result<notify::Event>| {
        let Ok(event) = res else {
            return;
        };
        // Ignore access events: the reload itself reads the file, and reacting
        // to that read would spin a feedback loop.
        if matches!(event.kind, notify::EventKind::Access(_)) {
            return;
        }
        let relevant = match &file_name {
            Some(name) => event
                .paths
                .iter()
                .any(|p| p.file_name() == Some(name.as_os_str())),
            None => true,
        };
        if relevant {
            // The receiver going away just means we are shutting down.
            let _ = tx.send(());
        }
    })
    .std_context("failed to create config watcher")?;
    watcher
        .watch(&dir, notify::RecursiveMode::NonRecursive)
        .with_std_context(|_| format!("failed to watch {}", dir.display()))?;
    Ok(watcher)
}

/// Awaits the next reload signal, or never resolves when reload is disabled.
async fn maybe_recv(rx: &mut Option<mpsc::UnboundedReceiver<()>>) -> Option<()> {
    match rx {
        Some(rx) => rx.recv().await,
        None => std::future::pending().await,
    }
}

/// Loads the endpoint secret key, generating and persisting one if needed.
///
/// `IROH_SECRET` takes preference. Otherwise the key is read from
/// `<dir>/secret.key` (32-byte lowercase hex), and if that file does not exist
/// a fresh key is generated and written there.
fn load_or_create_secret(dir: &Path) -> Result<SecretKey> {
    if let Ok(secret) = std::env::var("IROH_SECRET") {
        return SecretKey::from_str(&secret).std_context("invalid IROH_SECRET");
    }
    let path = dir.join("secret.key");
    match std::fs::read_to_string(&path) {
        Ok(contents) => SecretKey::from_str(contents.trim())
            .with_std_context(|_| format!("invalid secret key in {}", path.display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let key = SecretKey::generate();
            std::fs::create_dir_all(dir)
                .with_std_context(|_| format!("failed to create {}", dir.display()))?;
            let hex = data_encoding::HEXLOWER.encode(&key.to_bytes());
            std::fs::write(&path, &hex)
                .with_std_context(|_| format!("failed to write {}", path.display()))?;
            info!(path = %path.display(), "generated new secret key");
            Ok(key)
        }
        Err(e) => Err(e).with_std_context(|_| format!("failed to read {}", path.display())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_header_round_trip() {
        let (mut a, mut b) = tokio::io::duplex(64);
        let header = Header {
            name: "boo".into(),
            token: Some("s3cret".into()),
        };
        write_header(&mut a, &header).await.unwrap();
        let back = read_header(&mut b).await.unwrap();
        assert_eq!(back, header);
    }

    #[tokio::test]
    async fn test_header_round_trip_no_token() {
        let (mut a, mut b) = tokio::io::duplex(64);
        let header = Header {
            name: "boo".into(),
            token: None,
        };
        write_header(&mut a, &header).await.unwrap();
        assert_eq!(read_header(&mut b).await.unwrap(), header);
    }

    #[tokio::test]
    async fn test_read_header_rejects_oversize_length() {
        let (mut a, mut b) = tokio::io::duplex(64);
        let len = (MAX_HEADER_LEN as u32) + 1;
        a.write_all(&len.to_be_bytes()).await.unwrap();
        assert!(read_header(&mut b).await.is_err());
    }

    #[test]
    fn test_parse_config() {
        let id = "0".repeat(64);
        let toml = format!(
            r#"
            [[connect]]
            remote = "{id}"
            name = "boo"
            addr = "localhost:13414"
            token = "abc"

            [[accept]]
            name = "foo"
            addr = "localhost:31231"
            "#
        );
        let config: Config = toml::from_str(&toml).unwrap();
        // reload defaults to true when absent.
        assert!(config.reload);
        assert_eq!(config.connect.len(), 1);
        assert_eq!(config.connect[0].remote, id);
        assert_eq!(config.connect[0].token.as_deref(), Some("abc"));
        assert_eq!(config.accept.len(), 1);
        assert_eq!(config.accept[0].token, None);
    }

    #[test]
    fn test_parse_config_empty() {
        let config: Config = toml::from_str("").unwrap();
        assert!(config.reload);
        assert!(config.connect.is_empty());
        assert!(config.accept.is_empty());
    }

    #[test]
    fn test_config_round_trip() {
        let config = Config {
            reload: false,
            connect: vec![ConnectConfig {
                remote: "0".repeat(64),
                name: "boo".into(),
                addr: "127.0.0.1:1".into(),
                token: Some("tok".into()),
            }],
            accept: vec![AcceptConfig {
                name: "foo".into(),
                addr: "127.0.0.1:2".into(),
                token: None,
            }],
        };
        let toml = toml::to_string(&config).unwrap();
        let back: Config = toml::from_str(&toml).unwrap();
        assert_eq!(back.reload, config.reload);
        assert_eq!(back.connect, config.connect);
        assert_eq!(back.accept, config.accept);
    }

    #[test]
    fn test_generate_token_is_16_bytes() {
        let token = generate_token();
        let decoded = data_encoding::BASE32_NOPAD
            .decode(token.as_bytes())
            .unwrap();
        assert_eq!(decoded.len(), SECURE_TOKEN_BYTES);
    }

    #[test]
    fn test_build_routes_keeps_token() {
        let accept = vec![AcceptConfig {
            name: "foo".into(),
            addr: "127.0.0.1:1".into(),
            token: Some("tok".into()),
        }];
        let routes = build_routes(&accept);
        assert_eq!(routes.get("foo").unwrap().token.as_deref(), Some("tok"));
    }

    #[test]
    fn test_parse_remote_accepts_bare_id() {
        let id = "0".repeat(64);
        let addr = parse_remote(&id).unwrap();
        assert!(addr.is_empty());
        assert!(parse_remote("not-a-real-remote").is_err());
    }
}
