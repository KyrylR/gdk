#[macro_use]
extern crate serde_json;

pub mod error;
mod exchange_rates;

use gdk_common::util::{make_str, read_str};
use serde_json::Value;

use std::ffi::CString;
use std::io::Write;
use std::os::raw::c_char;
use std::str::FromStr;
use std::sync::{Arc, Once};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use gdk_common::model::InitParam;

use crate::error::Error;
use gdk_common::log::{self, debug, info, LevelFilter, Metadata, Record};
use gdk_common::session::{JsonError, Session};
use gdk_electrum::{sweep, ElectrumSession};
use serde::Serialize;
use simplicityhl::tracker::DefaultTracker;
use simplicityhl_core::ProgramError;
use std::cell::RefCell;

pub const GA_OK: i32 = 0;
pub const GA_ERROR: i32 = -1;
pub const GA_NOT_AUTHORIZED: i32 = -5;

pub struct GdkSession {
    pub backend: GdkBackend,
}

pub enum GdkBackend {
    // Rpc(RpcSession),
    Electrum(ElectrumSession),
}

impl From<Error> for JsonError {
    fn from(e: Error) -> Self {
        JsonError {
            message: e.to_string(),
            error: e.to_gdk_code(),
        }
    }
}

//
// Session & account management
//

static INIT_LOGGER: Once = Once::new();

#[unsafe(no_mangle)]
pub extern "C" fn GDKRUST_create_session(
    ret: *mut *const libc::c_void,
    network: *const c_char,
) -> i32 {
    let network: Value = match serde_json::from_str(&read_str(network)) {
        Ok(x) => x,
        Err(err) => {
            log::error!("error: {:?}", err);
            return GA_ERROR;
        }
    };

    match create_session(&network) {
        Err(err) => {
            log::error!("create_session error: {}", err);
            GA_ERROR
        }
        Ok(session) => {
            let session = Box::new(session);
            unsafe {
                *ret = Box::into_raw(session) as *mut libc::c_void;
            };
            GA_OK
        }
    }
}

/// Initialize the logging framework.
/// Note that once initialized it cannot be changed, only by reloading the library.
fn init_logging(level: LevelFilter) {
    #[cfg(target_os = "android")]
    INIT_LOGGER.call_once(|| {
        android_logger::init_once(
            android_logger::Config::default()
                .with_min_level(level.to_level().unwrap_or(log::Level::Error))
                .with_filter(
                    android_logger::FilterBuilder::new()
                        .parse("warn,gdk_rust=debug,gdk_electrum=debug")
                        .build(),
                ),
        )
    });

    #[cfg(not(target_os = "android"))]
    INIT_LOGGER.call_once(|| {
        log::set_logger(&LOGGER)
            .map(|()| log::set_max_level(level))
            .expect("cannot initialize logging");
    });
}

fn create_session(network: &Value) -> Result<GdkSession, Value> {
    info!("create_session {:?}", network);
    if !network.is_object() || !network.as_object().unwrap().contains_key("server_type") {
        log::error!("Expected network to be an object with a server_type key");
        return Err(GA_ERROR.into());
    }

    let parsed_network = serde_json::from_value(network.clone());
    if let Err(msg) = parsed_network {
        log::error!("Error parsing network {}", msg);
        return Err(GA_ERROR.into());
    }

    let parsed_network = parsed_network.unwrap();

    let backend = match network["server_type"].as_str() {
        // Some("rpc") => GDKRUST_session::Rpc( GDKRPC_session::create_session(parsed_network.unwrap()).unwrap() ),
        Some("electrum") => {
            let session = ElectrumSession::new(parsed_network)?;
            GdkBackend::Electrum(session)
        }
        _ => return Err(json!("server_type invalid")),
    };
    let gdk_session = GdkSession {
        backend,
    };
    Ok(gdk_session)
}

#[unsafe(no_mangle)]
pub extern "C" fn GDKRUST_call_session(
    ptr: *mut libc::c_void,
    method: *const c_char,
    input: *const c_char,
    output: *mut *const c_char,
) -> i32 {
    if ptr.is_null() {
        return GA_ERROR;
    }
    let sess: &mut GdkSession = unsafe { &mut *(ptr as *mut GdkSession) };
    let method = read_str(method);
    let input = read_str(input);

    match call_session(sess, &method, &input) {
        Ok(value) => {
            unsafe { *output = make_str(value.to_string()) };
            GA_OK
        }

        Err(err) => {
            let suppress_log =
                &err.message == "Scriptpubkey not found" && &method == "get_scriptpubkey_data";

            if !suppress_log {
                log::error!("error: {:?}", err);
            }

            let retv = if "id_invalid_pin" == err.error {
                GA_NOT_AUTHORIZED
            } else {
                GA_ERROR
            };

            unsafe { *output = make_str(to_string(&err)) };
            retv
        }
    }
}

fn call_session(sess: &mut GdkSession, method: &str, input: &str) -> Result<Value, JsonError> {
    let input = serde_json::from_str(input)?;

    if method == "exchange_rates" {
        let params = serde_json::from_value(input)?;

        let ticker = match &mut sess.backend {
            GdkBackend::Electrum(s) => exchange_rates::fetch_cached(s, &params),
        }?;

        let rate = ticker.map(|t| format!("{:.8}", t.rate)).unwrap_or_default();

        return Ok(json!({ "currencies": { params.currency.to_string(): rate } }));
    }

    // Redact inputs containing private data
    let methods_to_redact_in = vec![
        "login",
        "register_user",
        "encrypt_with_pin",
        "decrypt_with_pin",
        "create_subaccount",
        "credentials_from_pin_data",
        "set_master_blinding_key",
    ];
    let input_str = format!("{:?}", &input);
    let input_redacted = if methods_to_redact_in.contains(&method)
        || input_str.contains("pin")
        || input_str.contains("mnemonic")
        || input_str.contains("xprv")
    {
        "redacted".to_string()
    } else {
        input_str
    };

    info!("GDKRUST_call_session handle_call {} input {:?}", method, input_redacted);

    let res = match &mut sess.backend {
        GdkBackend::Electrum(s) => s.handle_call(&method, input),
    };

    let methods_to_redact_out =
        vec!["credentials_from_pin_data", "decrypt_with_pin", "get_master_blinding_key"];
    let mut output_redacted = if methods_to_redact_out.contains(&method) {
        "redacted".to_string()
    } else {
        format!("{:?}", res)
    };
    output_redacted.truncate(200);
    info!("GDKRUST_call_session {} output {:?}", method, output_redacted);

    res
}

#[unsafe(no_mangle)]
pub extern "C" fn GDKRUST_set_notification_handler(
    ptr: *mut libc::c_void,
    handler: extern "C" fn(*const libc::c_void, *const c_char),
    self_context: *const libc::c_void,
) -> i32 {
    if ptr.is_null() {
        return GA_ERROR;
    }
    let sess: &mut GdkSession = unsafe { &mut *(ptr as *mut GdkSession) };
    let backend = &mut sess.backend;

    match backend {
        GdkBackend::Electrum(s) => s.notify.set_native((handler, self_context)),
    };

    info!("set notification handler");

    GA_OK
}

#[unsafe(no_mangle)]
pub extern "C" fn GDKRUST_destroy_string(ptr: *mut c_char) {
    unsafe {
        // retake pointer and drop
        let _ = CString::from_raw(ptr);
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn GDKRUST_destroy_session(ptr: *mut libc::c_void) {
    unsafe {
        // retake pointer and drop
        let _ = Box::from_raw(ptr as *mut GdkSession);
    }
}

fn build_error(_method: &str, error: &Error) -> String {
    let message = error.to_string();
    let error = error.to_gdk_code();
    let json_error = JsonError {
        message,
        error,
    };
    to_string(&json_error)
}

fn to_string<T: Serialize>(value: &T) -> String {
    serde_json::to_string(&value)
        .expect("Default Serialize impl with maps containing only string keys")
}

#[unsafe(no_mangle)]
pub extern "C" fn GDKRUST_call(
    method: *const c_char,
    input: *const c_char,
    output: *mut *const c_char,
) -> i32 {
    let method = read_str(method);
    let input = read_str(input);
    debug!("GDKRUST_call {}", &method);

    let (error_value, result) = match handle_call(&method, &input) {
        Ok(value) => (GA_OK, value),
        Err(err) => (GA_ERROR, build_error(&method, &err)),
    };

    let result = make_str(result);
    unsafe {
        *output = result;
    }
    error_value
}

fn handle_call(method: &str, input: &str) -> Result<String, Error> {
    let start = Instant::now();

    let res = match method {
        "init" => {
            let param: InitParam = serde_json::from_str(input)?;
            init_logging(LevelFilter::from_str(&param.log_level).unwrap_or(LevelFilter::Off));
            gdk_registry::init(&param.registry_dir)?;
            // TODO: read more initialization params
            to_string(&json!("".to_string()))
        }
        "refresh_assets" => {
            let param: gdk_registry::RefreshAssetsParams = serde_json::from_str(input)?;
            to_string(&gdk_registry::refresh_assets(param)?)
        }
        "get_assets" => {
            let params: gdk_registry::GetAssetsParams = serde_json::from_str(input)?;
            to_string(&gdk_registry::get_assets(params)?)
        }
        "get_unspent_outputs_for_private_key" => {
            let param: sweep::SweepOpt = serde_json::from_str(input)?;
            to_string(&sweep::get_unspent_outputs_for_private_key(&param)?)
        }

        "options_test" => {
            info!("options_test called with input: {}", input);

            use simplicityhl::elements::confidential::{Asset, Value};
            use simplicityhl::simplicity::bitcoin::key::Keypair;
            use simplicityhl::simplicity::bitcoin::secp256k1;
            use simplicityhl::simplicity::bitcoin::secp256k1::Secp256k1;
            use simplicityhl::simplicity::elements::{self, AssetId, OutPoint, Txid};
            use simplicityhl::simplicity::hashes::Hash;
            use std::str::FromStr;

            use simplicityhl::elements::pset::PartiallySignedTransaction;
            use simplicityhl::elements::taproot::ControlBlock;
            use simplicityhl::elements::{ContractHash, Script};
            use simplicityhl::simplicity::jet::elements::ElementsUtxo;
            use simplicityhl_core::{LIQUID_TESTNET_TEST_ASSET_ID_STR, LIQUID_TESTNET_BITCOIN_ASSET};

            use simplicityhl_core::run_program;

            use simplicityhl::simplicity::jet::elements::ElementsEnv;

            use simplicityhl::tracker::TrackerLogLevel;
            use simplicityhl::elements::TxOut;
            use simplicityhl::elements::AddressParams;

            fn get_creation_pst(
                keypair: &Keypair,
                start_time: u32,
                expiry_time: u32,
                collateral_per_contract: u64,
                settlement_per_contract: u64,
            ) -> (
                (PartiallySignedTransaction, contracts::sdk::taproot_pubkey_gen::TaprootPubkeyGen),
                contracts::options::OptionsArguments,
            ) {
                let option_outpoint = OutPoint::new(Txid::from_slice(&[1; 32]).unwrap(), 0);
                let grantor_outpoint = OutPoint::new(Txid::from_slice(&[2; 32]).unwrap(), 0);

                let issuance_asset_entropy = [1; 32];

                let option_arguments = contracts::options::OptionsArguments {
                    start_time,
                    expiry_time,
                    collateral_per_contract,
                    settlement_per_contract,
                    collateral_asset_id: simplicityhl_core::LIQUID_TESTNET_BITCOIN_ASSET.into_inner().0,
                    settlement_asset_id: AssetId::from_str(simplicityhl_core::LIQUID_TESTNET_TEST_ASSET_ID_STR).unwrap()
                        .into_inner()
                        .0,
                    option_token_entropy: AssetId::generate_asset_entropy(
                        option_outpoint,
                        ContractHash::from_byte_array(issuance_asset_entropy),
                    )
                        .0,
                    grantor_token_entropy: AssetId::generate_asset_entropy(
                        grantor_outpoint,
                        ContractHash::from_byte_array(issuance_asset_entropy),
                    )
                        .0,
                };

                (
                    contracts::sdk::build_option_creation(
                        &keypair.public_key(),
                        (
                            option_outpoint,
                            TxOut {
                                asset: Asset::Explicit(*simplicityhl_core::LIQUID_TESTNET_BITCOIN_ASSET),
                                value: Value::Explicit(500),
                                nonce: elements::confidential::Nonce::Null,
                                script_pubkey: Script::new(),
                                witness: elements::TxOutWitness::default(),
                            },
                        ),
                        (
                            grantor_outpoint,
                            TxOut {
                                asset: Asset::Explicit(*simplicityhl_core::LIQUID_TESTNET_BITCOIN_ASSET),
                                value: Value::Explicit(1000),
                                nonce: elements::confidential::Nonce::Null,
                                script_pubkey: Script::new(),
                                witness: elements::TxOutWitness::default(),
                            },
                        ),
                        &option_arguments,
                        issuance_asset_entropy,
                        100,
                        &AddressParams::LIQUID_TESTNET,
                    ).unwrap(),
                    option_arguments,
                )
            }

            let keypair = Keypair::from_secret_key(
                &Secp256k1::new(),
                &secp256k1::SecretKey::from_slice(&[1u8; 32]).unwrap(),
            );

            let collateral_per_contract = 20;
            let settlement_per_contract = 25;

            let ((_, option_pubkey_gen), option_arguments) = get_creation_pst(
                &keypair,
                0,
                0,
                collateral_per_contract,
                settlement_per_contract,
            );

            let collateral_amount = 1000;
            let option_token_amount = collateral_amount / collateral_per_contract;
            let amount_to_burn = option_token_amount / 2;

            let (option_asset_id, _) = option_arguments.get_option_token_ids();
            let (grantor_asset_id, _) = option_arguments.get_grantor_token_ids();

            let (pst, option_branch) = contracts::sdk::build_option_cancellation(
                (
                    OutPoint::default(),
                    TxOut {
                        asset: Asset::Explicit(*LIQUID_TESTNET_BITCOIN_ASSET),
                        value: Value::Explicit(collateral_amount),
                        nonce: elements::confidential::Nonce::Null,
                        script_pubkey: option_pubkey_gen.address.script_pubkey(),
                        witness: elements::TxOutWitness::default(),
                    },
                ),
                (
                    OutPoint::default(),
                    TxOut {
                        asset: Asset::Explicit(option_asset_id),
                        value: Value::Explicit(option_token_amount),
                        nonce: elements::confidential::Nonce::Null,
                        script_pubkey: Script::new(),
                        witness: elements::TxOutWitness::default(),
                    },
                ),
                (
                    OutPoint::default(),
                    TxOut {
                        asset: Asset::Explicit(grantor_asset_id),
                        value: Value::Explicit(option_token_amount),
                        nonce: elements::confidential::Nonce::Null,
                        script_pubkey: Script::new(),
                        witness: elements::TxOutWitness::default(),
                    },
                ),
                (
                    OutPoint::default(),
                    TxOut {
                        asset: Asset::Explicit(*LIQUID_TESTNET_BITCOIN_ASSET),
                        value: Value::Explicit(100),
                        nonce: elements::confidential::Nonce::Null,
                        script_pubkey: Script::new(),
                        witness: elements::TxOutWitness::default(),
                    },
                ),
                &option_arguments,
                amount_to_burn,
                50,
            ).unwrap();

            let program = contracts::options::get_compiled_options_program(&option_arguments);

            let env = ElementsEnv::new(
                Arc::new(pst.extract_tx().unwrap()),
                vec![ElementsUtxo {
                    script_pubkey: option_pubkey_gen.address.script_pubkey(),
                    asset: Asset::Explicit(*LIQUID_TESTNET_BITCOIN_ASSET),
                    value: Value::Explicit(collateral_amount),
                }],
                0,
                simplicityhl::simplicity::Cmr::from_byte_array([0; 32]),
                ControlBlock::from_slice(&[0xc0; 33]).unwrap(),
                None,
                elements::BlockHash::all_zeros(),
            );

            let witness_values = contracts::options::build_witness::build_option_witness(option_branch);

            let satisfied = program
                .satisfy(witness_values)
                .map_err(ProgramError::WitnessSatisfaction).unwrap();

            let logs: RefCell<Vec<String>> = RefCell::new(Vec::new());

            let mut tracker = DefaultTracker::new(satisfied.debug_symbols())
                .with_debug_sink(|label, value| {
                    logs.borrow_mut().push(format!("DBG: {label} = {value}"));
                })
                .with_jet_trace_sink(|jet, args, result| {
                    let args_str = match args {
                        Some(args) => args.iter().map(|v| v.to_string()).collect::<Vec<_>>().join(", "),
                        None => "...".to_string(),
                    };
                    let result_str = match result {
                        Some(v) => v.to_string(),
                        None => "[failed]".to_string(),
                    };
                    logs.borrow_mut().push(format!("{jet:?}({args_str}) = {result_str}"));
                })
                .with_warning_sink(|message| {
                    logs.borrow_mut().push(format!("WARN: {message}"));
                });

            let pruned = satisfied.redeem().prune_with_tracker(&env, &mut tracker);

            let collected_logs = logs.borrow().clone();

            to_string(&json!({
                "status": "ok",
                "result": pruned.is_ok(),
                "message": format!("options_test executed successfully -- result: {}", pruned.is_ok()),
                "logs": collected_logs
            }))
        }

        _ => {
            return Err(Error::MethodNotFound {
                method: method.to_string(),
                in_session: false,
            })
        }
    };

    info!("`{}` took {:?}", method, start.elapsed());

    Ok(res)
}

#[cfg(not(target_os = "android"))]
static LOGGER: SimpleLogger = SimpleLogger;

pub struct SimpleLogger;

impl log::Log for SimpleLogger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        let level = metadata.level();
        if level > log::Level::Debug {
            level <= log::max_level()
        } else {
            level <= log::max_level()
                && !metadata.target().starts_with("rustls")
                && !metadata.target().starts_with("electrum_client")
        }
    }

    fn log(&self, record: &Record) {
        if self.enabled(record.metadata()) {
            let ts = SystemTime::now().duration_since(UNIX_EPOCH).expect("Time went backwards");
            let _ = writeln!(
                std::io::stdout(),
                "{:02}.{:03} {} - {}",
                ts.as_secs() % 60,
                ts.subsec_millis(),
                record.level(),
                record.args()
            );
        }
    }

    fn flush(&self) {}
}
