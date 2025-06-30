use axum::{
    extract::Path,
    response::Json,
    routing::{get, post},
    Router,
};
use serde::{Deserialize, Serialize};
use solana_sdk::{
    instruction::Instruction,
    pubkey::Pubkey,
    signature::{Keypair, Signature, Signer},
    system_instruction,
};
use spl_token::instruction as spl_instruction;
use std::str::FromStr;
use tower_http::cors::CorsLayer;
use tracing::info;

// Response types
#[derive(Serialize)]
struct ApiResponse<T> {
    success: bool,
    data: Option<T>,
    error: Option<String>,
}

impl<T> ApiResponse<T> {
    fn success(data: T) -> Self {
        Self {
            success: true,
            data: Some(data),
            error: None,
        }
    }

    fn error(message: String) -> Self {
        Self {
            success: false,
            data: None,
            error: Some(message),
        }
    }
}

// Request/Response structures
#[derive(Serialize)]
struct KeypairResponse {
    public_key: String,
    secret_key: String,
}

#[derive(Deserialize)]
struct SignMessageRequest {
    message: String,
    secret_key: String,
}

#[derive(Serialize)]
struct SignMessageResponse {
    signature: String,
    public_key: String,
}

#[derive(Deserialize)]
struct VerifyMessageRequest {
    message: String,
    signature: String,
    public_key: String,
}

#[derive(Serialize)]
struct VerifyMessageResponse {
    valid: bool,
}

#[derive(Deserialize)]
struct CreateTokenAccountRequest {
    owner_pubkey: String,
    mint_pubkey: String,
    payer_pubkey: String,
}

#[derive(Serialize)]
struct TokenAccountResponse {
    token_account: String,
    instruction: String, // Base58 encoded instruction
}

#[derive(Deserialize)]
struct TransferTokenRequest {
    source: String,
    destination: String,
    owner: String,
    amount: u64,
}

#[derive(Serialize)]
struct InstructionResponse {
    instruction: String, // Base58 encoded instruction
    accounts: Vec<AccountInfo>,
}

#[derive(Serialize)]
struct AccountInfo {
    pubkey: String,
    is_signer: bool,
    is_writable: bool,
}

#[derive(Deserialize)]
struct TransferSolRequest {
    from_pubkey: String,
    to_pubkey: String,
    lamports: u64,
}

// Utility functions
fn encode_instruction(instruction: &Instruction) -> String {
    bs58::encode(bincode::serialize(instruction).unwrap()).into_string()
}

fn keypair_to_response(keypair: &Keypair) -> KeypairResponse {
    KeypairResponse {
        public_key: keypair.pubkey().to_string(),
        secret_key: bs58::encode(&keypair.to_bytes()).into_string(),
    }
}

// Route handlers
async fn health() -> Json<ApiResponse<&'static str>> {
    Json(ApiResponse::success("Solana HTTP server is running"))
}

async fn generate_keypair() -> Json<ApiResponse<KeypairResponse>> {
    let keypair = Keypair::new();
    Json(ApiResponse::success(keypair_to_response(&keypair)))
}

async fn get_public_key(Path(secret_key): Path<String>) -> Json<ApiResponse<String>> {
    match bs58::decode(&secret_key).into_vec() {
        Ok(bytes) => {
            if bytes.len() == 64 {
                match Keypair::try_from(bytes.as_slice()) {
                    Ok(keypair) => Json(ApiResponse::success(keypair.pubkey().to_string())),
                    Err(_) => Json(ApiResponse::error("Invalid secret key format".to_string())),
                }
            } else {
                Json(ApiResponse::error("Invalid secret key length".to_string()))
            }
        }
        Err(_) => Json(ApiResponse::error("Invalid base58 encoding".to_string())),
    }
}

async fn sign_message(Json(req): Json<SignMessageRequest>) -> Json<ApiResponse<SignMessageResponse>> {
    match bs58::decode(&req.secret_key).into_vec() {
        Ok(bytes) => {
            if bytes.len() == 64 {
                match Keypair::try_from(bytes.as_slice()) {
                    Ok(keypair) => {
                        let message_bytes = req.message.as_bytes();
                        let signature = keypair.sign_message(message_bytes);
                        Json(ApiResponse::success(SignMessageResponse {
                            signature: signature.to_string(),
                            public_key: keypair.pubkey().to_string(),
                        }))
                    }
                    Err(_) => Json(ApiResponse::error("Invalid secret key format".to_string())),
                }
            } else {
                Json(ApiResponse::error("Invalid secret key length".to_string()))
            }
        }
        Err(_) => Json(ApiResponse::error("Invalid base58 encoding for secret key".to_string())),
    }
}

async fn verify_message(Json(req): Json<VerifyMessageRequest>) -> Json<ApiResponse<VerifyMessageResponse>> {
    match (
        Pubkey::from_str(&req.public_key),
        Signature::from_str(&req.signature),
    ) {
        (Ok(pubkey), Ok(signature)) => {
            let message_bytes = req.message.as_bytes();
            let valid = signature.verify(&pubkey.to_bytes(), message_bytes);
            Json(ApiResponse::success(VerifyMessageResponse { valid }))
        }
        _ => Json(ApiResponse::error("Invalid public key or signature format".to_string())),
    }
}

async fn create_associated_token_account(
    Json(req): Json<CreateTokenAccountRequest>,
) -> Json<ApiResponse<TokenAccountResponse>> {
    match (
        Pubkey::from_str(&req.owner_pubkey),
        Pubkey::from_str(&req.mint_pubkey),
        Pubkey::from_str(&req.payer_pubkey),
    ) {
        (Ok(owner), Ok(mint), Ok(payer)) => {
            let associated_token_account = 
                spl_associated_token_account::get_associated_token_address(&owner, &mint);
            
            let instruction = spl_associated_token_account::instruction::create_associated_token_account(
                &payer,
                &owner,
                &mint,
                &spl_token::id(),
            );

            Json(ApiResponse::success(TokenAccountResponse {
                token_account: associated_token_account.to_string(),
                instruction: encode_instruction(&instruction),
            }))
        }
        _ => Json(ApiResponse::error("Invalid pubkey format".to_string())),
    }
}

async fn create_transfer_token_instruction(
    Json(req): Json<TransferTokenRequest>,
) -> Json<ApiResponse<InstructionResponse>> {
    match (
        Pubkey::from_str(&req.source),
        Pubkey::from_str(&req.destination),
        Pubkey::from_str(&req.owner),
    ) {
        (Ok(source), Ok(destination), Ok(owner)) => {
            let instruction = spl_instruction::transfer(
                &spl_token::id(),
                &source,
                &destination,
                &owner,
                &[],
                req.amount,
            ).unwrap();

            let accounts = instruction.accounts.iter().map(|acc| AccountInfo {
                pubkey: acc.pubkey.to_string(),
                is_signer: acc.is_signer,
                is_writable: acc.is_writable,
            }).collect();

            Json(ApiResponse::success(InstructionResponse {
                instruction: encode_instruction(&instruction),
                accounts,
            }))
        }
        _ => Json(ApiResponse::error("Invalid pubkey format".to_string())),
    }
}

async fn create_transfer_sol_instruction(
    Json(req): Json<TransferSolRequest>,
) -> Json<ApiResponse<InstructionResponse>> {
    match (
        Pubkey::from_str(&req.from_pubkey),
        Pubkey::from_str(&req.to_pubkey),
    ) {
        (Ok(from), Ok(to)) => {
            let instruction = system_instruction::transfer(&from, &to, req.lamports);
            
            let accounts = instruction.accounts.iter().map(|acc| AccountInfo {
                pubkey: acc.pubkey.to_string(),
                is_signer: acc.is_signer,
                is_writable: acc.is_writable,
            }).collect();

            Json(ApiResponse::success(InstructionResponse {
                instruction: encode_instruction(&instruction),
                accounts,
            }))
        }
        _ => Json(ApiResponse::error("Invalid pubkey format".to_string())),
    }
}

async fn get_token_account_address(
    Path((owner, mint)): Path<(String, String)>,
) -> Json<ApiResponse<String>> {
    match (Pubkey::from_str(&owner), Pubkey::from_str(&mint)) {
        (Ok(owner_pubkey), Ok(mint_pubkey)) => {
            let associated_token_account = 
                spl_associated_token_account::get_associated_token_address(&owner_pubkey, &mint_pubkey);
            Json(ApiResponse::success(associated_token_account.to_string()))
        }
        _ => Json(ApiResponse::error("Invalid pubkey format".to_string())),
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize tracing
    tracing_subscriber::fmt::init();

    // Build the router
    let app = Router::new()
        .route("/health", get(health))
        .route("/keypair/generate", post(generate_keypair))
        .route("/keypair/public/{secret_key}", get(get_public_key))
        .route("/message/sign", post(sign_message))
        .route("/message/verify", post(verify_message))
        .route("/token/account/create", post(create_associated_token_account))
        .route("/token/account/address/{owner}/{mint}", get(get_token_account_address))
        .route("/token/transfer", post(create_transfer_token_instruction))
        .route("/sol/transfer", post(create_transfer_sol_instruction))
        .layer(CorsLayer::permissive());

    let port = std::env::var("PORT").unwrap_or_else(|_| "3000".to_string());
    let addr = format!("0.0.0.0:{}", port);
    
    info!("Starting Solana HTTP server on {}", addr);
    
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}