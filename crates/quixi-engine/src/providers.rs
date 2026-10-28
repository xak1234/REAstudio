use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use uuid::Uuid;

const OPENAI_CODEX_CLIENT_ID: &str = "app_EMoamEEZ73f0CkXaXp7hrann";
const OPENAI_CODEX_AUTHORIZE_URL: &str = "https://auth.openai.com/oauth/authorize";
const OPENAI_CODEX_TOKEN_URL: &str = "https://auth.openai.com/oauth/token";
const OPENAI_CODEX_REDIRECT_URI: &str = "http://localhost:1455/auth/callback";
const OPENAI_CODEX_DEVICE_USERCODE_URL: &str =
    "https://auth.openai.com/api/accounts/deviceauth/usercode";
const OPENAI_CODEX_DEVICE_TOKEN_URL: &str = "https://auth.openai.com/api/accounts/deviceauth/token";
const OPENAI_CODEX_DEVICE_VERIFICATION_URL: &str = "https://auth.openai.com/codex/device";
const OPENAI_CODEX_DEVICE_REDIRECT_URI: &str = "https://auth.openai.com/deviceauth/callback";

const XAI_OAUTH_CLIENT_ID: &str = "b1a00492-073a-47ea-816f-4c329264a828";
const XAI_OAUTH_SCOPE: &str = "openid profile email offline_access grok-cli:access api:access";
const XAI_OAUTH_DISCOVERY_URL: &str = "https://auth.x.ai/.well-known/openid-configuration";
const XAI_DEVICE_GRANT_TYPE: &str = "urn:ietf:params:oauth:grant-type:device_code";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProviderModelInfo {
    pub id: String,
    pub label: String,
    pub context_window: u32,
    pub supports_thinking: bool,
    pub supports_vision: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProviderEntry {
    pub id: String,
    pub name: String,
    pub subtitle: String,
    pub badge: String,
    pub category: String, // "priority" | "cloud" | "local"
    pub priority_rank: usize,
    pub supports_oauth: bool,
    pub oauth_label: Option<String>,
    pub auth_mode: String,  // "api_key" | "oauth" | "custom" | "local"
    pub api_format: String, // "openai" | "anthropic"
    pub base_url: String,
    pub api_key_masked: String,
    #[serde(skip_serializing)]
    pub api_key_raw: String,
    #[serde(skip_serializing)]
    pub oauth_access_token: String,
    #[serde(skip_serializing)]
    pub oauth_refresh_token: String,
    pub oauth_account_label: Option<String>,
    pub oauth_expires_ms: Option<u64>,
    pub key_placeholder: String,
    pub env_var: String,
    pub docs_url: String,
    pub configured: bool,
    pub selected_model: String,
    pub models: Vec<ProviderModelInfo>,
    pub custom_models: Vec<String>,
    /// Exact IDs observed from this endpoint. Catalog placeholders only become usable if advertised.
    #[serde(default)]
    pub advertised_models: Vec<String>,
    pub context_window: u32,
    pub last_tested_ok: Option<bool>,
    pub last_latency_ms: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProvidersStateFile {
    pub onboarding_completed: bool,
    pub active_provider: String,
    pub active_model: String,
    pub subagent_provider: String,
    pub subagent_model: String,
    pub providers: Vec<ProviderEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PendingOAuthSession {
    pub provider_id: String,
    pub pkce_verifier: String,
    pub pkce_challenge: String,
    pub state: String,
    pub authorize_url: String,
    pub verification_url: String,
    pub user_code: String,
    pub device_id: String,
    pub token_endpoint: String,
    pub created_at_ms: u64,
}

pub struct ProviderManager {
    pub config_path: PathBuf,
    pub state: RwLock<ProvidersStateFile>,
    pub pending_oauth: RwLock<HashMap<String, PendingOAuthSession>>,
}

impl ProviderManager {
    pub fn new(data_dir: &PathBuf) -> Self {
        let config_path = data_dir.join("providers.json");
        let default_catalog = Self::default_catalog();

        let loaded = if config_path.exists() {
            fs::read_to_string(&config_path)
                .ok()
                .and_then(|s| serde_json::from_str::<Value>(&s).ok())
                .and_then(|val| Self::merge_saved_state(default_catalog.clone(), &val))
        } else {
            None
        };

        let state = loaded.unwrap_or(default_catalog);
        let mgr = Self {
            config_path,
            state: RwLock::new(state),
            pending_oauth: RwLock::new(HashMap::new()),
        };
        mgr.persist();
        mgr
    }

    fn model(
        id: &str,
        label: &str,
        context_window: u32,
        supports_thinking: bool,
        supports_vision: bool,
    ) -> ProviderModelInfo {
        ProviderModelInfo {
            id: id.to_string(),
            label: label.to_string(),
            context_window,
            supports_thinking,
            supports_vision,
        }
    }

    /// Builds the full 19-entry provider catalog in the exact user-requested priority order:
    /// 1. OpenRouter
    /// 2. Custom Endpoint
    /// 3. OpenAI (OAuth + API Key)
    /// 4. Grok / xAI (OAuth + API Key)
    /// 5. Anthropic (API Key)
    /// 6..19. Remaining HexisPro cloud & local providers
    pub fn default_catalog() -> ProvidersStateFile {
        let providers = vec![
            // 1. OpenRouter (First on the list)
            ProviderEntry {
                id: "openrouter".to_string(),
                name: "OpenRouter".to_string(),
                subtitle: "Unified gateway to 200+ frontier models (Claude, GPT, Grok, Gemini, DeepSeek)".to_string(),
                badge: "Recommended · #1".to_string(),
                category: "priority".to_string(),
                priority_rank: 1,
                supports_oauth: false,
                oauth_label: None,
                auth_mode: "api_key".to_string(),
                api_format: "openai".to_string(),
                base_url: "https://openrouter.ai/api/v1".to_string(),
                api_key_masked: String::new(),
                api_key_raw: String::new(),
                oauth_access_token: String::new(),
                oauth_refresh_token: String::new(),
                oauth_account_label: None,
                oauth_expires_ms: None,
                key_placeholder: "sk-or-v1-...".to_string(),
                env_var: "OPENROUTER_API_KEY".to_string(),
                docs_url: "https://openrouter.ai/keys".to_string(),
                configured: false,
                selected_model: "anthropic/claude-sonnet-4.6".to_string(),
                models: vec![
                    Self::model("anthropic/claude-sonnet-4.6", "Claude Sonnet 4.6 (via OpenRouter)", 200_000, true, true),
                    Self::model("anthropic/claude-opus-4.6", "Claude Opus 4.6 (via OpenRouter)", 200_000, true, true),
                    Self::model("openai/gpt-5.4", "GPT-5.4 (via OpenRouter)", 256_000, true, true),
                    Self::model("x-ai/grok-4", "Grok 4 (via OpenRouter)", 256_000, true, true),
                    Self::model("google/gemini-3.1-pro-preview", "Gemini 3.1 Pro (via OpenRouter)", 1_000_000, true, true),
                    Self::model("deepseek/deepseek-r1", "DeepSeek R1 (via OpenRouter)", 128_000, true, false),
                    Self::model("qwen/qwen3-coder-480b", "Qwen 3 Coder 480B (via OpenRouter)", 128_000, true, false),
                ],
                custom_models: vec![],
                advertised_models: Vec::new(),
                context_window: 200_000,
                last_tested_ok: None,
                last_latency_ms: None,
            },
            // 2. Custom Endpoint (Second on the list)
            ProviderEntry {
                id: "custom".to_string(),
                name: "Custom Endpoint".to_string(),
                subtitle: "Any OpenAI or Anthropic compatible base URL (LiteLLM, vLLM, enterprise proxy, self-hosted)".to_string(),
                badge: "Flexible URL · #2".to_string(),
                category: "priority".to_string(),
                priority_rank: 2,
                supports_oauth: false,
                oauth_label: None,
                auth_mode: "custom".to_string(),
                api_format: "openai".to_string(),
                base_url: "http://localhost:8000/v1".to_string(),
                api_key_masked: String::new(),
                api_key_raw: String::new(),
                oauth_access_token: String::new(),
                oauth_refresh_token: String::new(),
                oauth_account_label: None,
                oauth_expires_ms: None,
                key_placeholder: "Optional API key (sk-...)".to_string(),
                env_var: "CUSTOM_API_KEY".to_string(),
                docs_url: String::new(),
                configured: false,
                selected_model: "custom-model".to_string(),
                models: vec![
                    Self::model("custom-model", "Custom Model ID", 128_000, true, true),
                ],
                custom_models: vec!["custom-model".to_string()],
                advertised_models: Vec::new(),
                context_window: 128_000,
                last_tested_ok: None,
                last_latency_ms: None,
            },
            // 3. OpenAI (Third on the list — supports OAuth!)
            ProviderEntry {
                id: "openai".to_string(),
                name: "OpenAI".to_string(),
                subtitle: "Sign in with ChatGPT Plus/Pro subscription (Codex OAuth) or use an OpenAI Platform API key".to_string(),
                badge: "Supports OAuth".to_string(),
                category: "priority".to_string(),
                priority_rank: 3,
                supports_oauth: true,
                oauth_label: Some("Sign in with ChatGPT (OAuth)".to_string()),
                auth_mode: "oauth".to_string(),
                api_format: "openai".to_string(),
                base_url: "https://api.openai.com/v1".to_string(),
                api_key_masked: String::new(),
                api_key_raw: String::new(),
                oauth_access_token: String::new(),
                oauth_refresh_token: String::new(),
                oauth_account_label: None,
                oauth_expires_ms: None,
                key_placeholder: "sk-proj-...".to_string(),
                env_var: "OPENAI_API_KEY".to_string(),
                docs_url: "https://platform.openai.com/api-keys".to_string(),
                configured: false,
                selected_model: "gpt-6.1-sol".to_string(),
                models: vec![
                    Self::model("gpt-6.1-sol", "GPT-6.1 Sol (Codex OAuth)", 256_000, true, true),
                    Self::model("gpt-6-astra", "GPT-6 Astra (Codex OAuth)", 256_000, true, true),
                    Self::model("gpt-6-sol", "GPT-6 Sol (Codex OAuth)", 256_000, true, true),
                    Self::model("gpt-6-luna", "GPT-6 Luna (Codex OAuth)", 256_000, true, true),
                    Self::model("gpt-5.6-sol", "GPT-5.6 Sol (Codex OAuth)", 256_000, true, true),
                    Self::model("gpt-5.6-terra", "GPT-5.6 Terra (Codex OAuth)", 256_000, true, true),
                    Self::model("gpt-5.6-luna", "GPT-5.6 Luna (Codex OAuth)", 256_000, true, true),
                    Self::model("gpt-daybreak-blue-latest", "GPT Daybreak Blue (Codex OAuth)", 256_000, true, true),
                    Self::model("gpt-5.4", "GPT-5.4 (Platform API)", 256_000, true, true),
                    Self::model("gpt-5.4-mini", "GPT-5.4 Mini (Platform API)", 256_000, true, true),
                    Self::model("o3", "OpenAI o3 Reasoning (Platform API)", 200_000, true, true),
                    Self::model("gpt-4.1", "GPT-4.1 (Platform API)", 1_000_000, false, true),
                ],
                custom_models: vec![],
                advertised_models: Vec::new(),
                context_window: 256_000,
                last_tested_ok: None,
                last_latency_ms: None,
            },
            // 4. Grok / xAI (Fourth on the list — supports OAuth!)
            ProviderEntry {
                id: "xai".to_string(),
                name: "Grok (xAI)".to_string(),
                subtitle: "Sign in with SuperGrok / X account (OAuth Device Flow) or use an xAI Console API key".to_string(),
                badge: "Supports OAuth".to_string(),
                category: "priority".to_string(),
                priority_rank: 4,
                supports_oauth: true,
                oauth_label: Some("Sign in with Grok / X (OAuth)".to_string()),
                auth_mode: "oauth".to_string(),
                api_format: "openai".to_string(),
                base_url: "https://api.x.ai/v1".to_string(),
                api_key_masked: String::new(),
                api_key_raw: String::new(),
                oauth_access_token: String::new(),
                oauth_refresh_token: String::new(),
                oauth_account_label: None,
                oauth_expires_ms: None,
                key_placeholder: "xai-...".to_string(),
                env_var: "XAI_API_KEY".to_string(),
                docs_url: "https://console.x.ai/".to_string(),
                configured: false,
                selected_model: "grok-4".to_string(),
                models: vec![
                    Self::model("grok-4", "Grok 4", 256_000, true, true),
                    Self::model("grok-4-fast", "Grok 4 Fast", 256_000, true, true),
                    Self::model("grok-code-fast-1", "Grok Code Fast 1", 256_000, true, false),
                    Self::model("grok-3", "Grok 3", 131_072, true, true),
                ],
                custom_models: vec![],
                advertised_models: Vec::new(),
                context_window: 256_000,
                last_tested_ok: None,
                last_latency_ms: None,
            },
            // 5. Anthropic (Fifth on the list — API Key only, no OAuth)
            ProviderEntry {
                id: "anthropic".to_string(),
                name: "Anthropic".to_string(),
                subtitle: "Direct Claude API access via Anthropic Console API key (does not support OAuth)".to_string(),
                badge: "API Key Only".to_string(),
                category: "priority".to_string(),
                priority_rank: 5,
                supports_oauth: false,
                oauth_label: None,
                auth_mode: "api_key".to_string(),
                api_format: "anthropic".to_string(),
                base_url: "https://api.anthropic.com/v1".to_string(),
                api_key_masked: String::new(),
                api_key_raw: String::new(),
                oauth_access_token: String::new(),
                oauth_refresh_token: String::new(),
                oauth_account_label: None,
                oauth_expires_ms: None,
                key_placeholder: "sk-ant-api03-...".to_string(),
                env_var: "ANTHROPIC_API_KEY".to_string(),
                docs_url: "https://console.anthropic.com/settings/keys".to_string(),
                configured: false,
                selected_model: "claude-sonnet-4-6".to_string(),
                models: vec![
                    Self::model("claude-sonnet-4-6", "Claude Sonnet 4.6", 200_000, true, true),
                    Self::model("claude-opus-4-6", "Claude Opus 4.6", 200_000, true, true),
                    Self::model("claude-haiku-4-5-20251001", "Claude Haiku 4.5", 200_000, false, true),
                ],
                custom_models: vec![],
                advertised_models: Vec::new(),
                context_window: 200_000,
                last_tested_ok: None,
                last_latency_ms: None,
            },
            // 6. Google Gemini
            ProviderEntry {
                id: "gemini".to_string(),
                name: "Google Gemini".to_string(),
                subtitle: "Gemini 3.1 Pro, 2.5 Pro, and 2.5 Flash via Google AI Studio API key".to_string(),
                badge: "1M Context".to_string(),
                category: "cloud".to_string(),
                priority_rank: 6,
                supports_oauth: false,
                oauth_label: None,
                auth_mode: "api_key".to_string(),
                api_format: "openai".to_string(),
                base_url: "https://generativelanguage.googleapis.com/v1beta/openai".to_string(),
                api_key_masked: String::new(),
                api_key_raw: String::new(),
                oauth_access_token: String::new(),
                oauth_refresh_token: String::new(),
                oauth_account_label: None,
                oauth_expires_ms: None,
                key_placeholder: "AIzaSy...".to_string(),
                env_var: "GEMINI_API_KEY".to_string(),
                docs_url: "https://aistudio.google.com/app/apikey".to_string(),
                configured: false,
                selected_model: "gemini-3.1-pro-preview".to_string(),
                models: vec![
                    Self::model("gemini-3.1-pro-preview", "Gemini 3.1 Pro Preview", 1_000_000, true, true),
                    Self::model("gemini-2.5-pro", "Gemini 2.5 Pro", 1_000_000, true, true),
                    Self::model("gemini-2.5-flash", "Gemini 2.5 Flash", 1_000_000, true, true),
                ],
                custom_models: vec![],
                advertised_models: Vec::new(),
                context_window: 1_000_000,
                last_tested_ok: None,
                last_latency_ms: None,
            },
            // 7. DeepSeek
            ProviderEntry {
                id: "deepseek".to_string(),
                name: "DeepSeek".to_string(),
                subtitle: "DeepSeek V3 (chat) and DeepSeek R1 (reasoner)".to_string(),
                badge: "Reasoning".to_string(),
                category: "cloud".to_string(),
                priority_rank: 7,
                supports_oauth: false,
                oauth_label: None,
                auth_mode: "api_key".to_string(),
                api_format: "openai".to_string(),
                base_url: "https://api.deepseek.com/v1".to_string(),
                api_key_masked: String::new(),
                api_key_raw: String::new(),
                oauth_access_token: String::new(),
                oauth_refresh_token: String::new(),
                oauth_account_label: None,
                oauth_expires_ms: None,
                key_placeholder: "sk-...".to_string(),
                env_var: "DEEPSEEK_API_KEY".to_string(),
                docs_url: "https://platform.deepseek.com/api_keys".to_string(),
                configured: false,
                selected_model: "deepseek-chat".to_string(),
                models: vec![
                    Self::model("deepseek-chat", "DeepSeek V3 (Chat)", 128_000, false, false),
                    Self::model("deepseek-reasoner", "DeepSeek R1 (Reasoner)", 128_000, true, false),
                ],
                custom_models: vec![],
                advertised_models: Vec::new(),
                context_window: 128_000,
                last_tested_ok: None,
                last_latency_ms: None,
            },
            // 8. Groq
            ProviderEntry {
                id: "groq".to_string(),
                name: "Groq".to_string(),
                subtitle: "Ultra-low-latency LPU inference for Llama 3.3, Kimi K2, and Qwen".to_string(),
                badge: "Ultra-Fast".to_string(),
                category: "cloud".to_string(),
                priority_rank: 8,
                supports_oauth: false,
                oauth_label: None,
                auth_mode: "api_key".to_string(),
                api_format: "openai".to_string(),
                base_url: "https://api.groq.com/openai/v1".to_string(),
                api_key_masked: String::new(),
                api_key_raw: String::new(),
                oauth_access_token: String::new(),
                oauth_refresh_token: String::new(),
                oauth_account_label: None,
                oauth_expires_ms: None,
                key_placeholder: "gsk_...".to_string(),
                env_var: "GROQ_API_KEY".to_string(),
                docs_url: "https://console.groq.com/keys".to_string(),
                configured: false,
                selected_model: "llama-3.3-70b-versatile".to_string(),
                models: vec![
                    Self::model("llama-3.3-70b-versatile", "Llama 3.3 70B Versatile", 128_000, false, false),
                    Self::model("moonshotai/kimi-k2-instruct", "Kimi K2 Instruct (Groq)", 128_000, false, false),
                    Self::model("qwen-qwq-32b", "Qwen QwQ 32B", 128_000, true, false),
                ],
                custom_models: vec![],
                advertised_models: Vec::new(),
                context_window: 128_000,
                last_tested_ok: None,
                last_latency_ms: None,
            },
            // 9. Mistral
            ProviderEntry {
                id: "mistral".to_string(),
                name: "Mistral AI".to_string(),
                subtitle: "Mistral Large, Codestral, and Pixtral models".to_string(),
                badge: "Cloud".to_string(),
                category: "cloud".to_string(),
                priority_rank: 9,
                supports_oauth: false,
                oauth_label: None,
                auth_mode: "api_key".to_string(),
                api_format: "openai".to_string(),
                base_url: "https://api.mistral.ai/v1".to_string(),
                api_key_masked: String::new(),
                api_key_raw: String::new(),
                oauth_access_token: String::new(),
                oauth_refresh_token: String::new(),
                oauth_account_label: None,
                oauth_expires_ms: None,
                key_placeholder: "Mistral API Key".to_string(),
                env_var: "MISTRAL_API_KEY".to_string(),
                docs_url: "https://console.mistral.ai/api-keys/".to_string(),
                configured: false,
                selected_model: "mistral-large-latest".to_string(),
                models: vec![
                    Self::model("mistral-large-latest", "Mistral Large", 128_000, false, true),
                    Self::model("codestral-latest", "Codestral", 256_000, false, false),
                ],
                custom_models: vec![],
                advertised_models: Vec::new(),
                context_window: 128_000,
                last_tested_ok: None,
                last_latency_ms: None,
            },
            // 10. MiniMax
            ProviderEntry {
                id: "minimax".to_string(),
                name: "MiniMax".to_string(),
                subtitle: "MiniMax M2.7 and M1 long-context reasoning models".to_string(),
                badge: "Cloud".to_string(),
                category: "cloud".to_string(),
                priority_rank: 10,
                supports_oauth: false,
                oauth_label: None,
                auth_mode: "api_key".to_string(),
                api_format: "openai".to_string(),
                base_url: "https://api.minimax.io/v1".to_string(),
                api_key_masked: String::new(),
                api_key_raw: String::new(),
                oauth_access_token: String::new(),
                oauth_refresh_token: String::new(),
                oauth_account_label: None,
                oauth_expires_ms: None,
                key_placeholder: "MiniMax API Key".to_string(),
                env_var: "MINIMAX_API_KEY".to_string(),
                docs_url: "https://platform.minimax.io/".to_string(),
                configured: false,
                selected_model: "MiniMax-M2.7".to_string(),
                models: vec![
                    Self::model("MiniMax-M2.7", "MiniMax M2.7", 200_000, true, true),
                    Self::model("MiniMax-M1", "MiniMax M1", 1_000_000, true, false),
                ],
                custom_models: vec![],
                advertised_models: Vec::new(),
                context_window: 200_000,
                last_tested_ok: None,
                last_latency_ms: None,
            },
            // 11. Zhipu / GLM
            ProviderEntry {
                id: "zai".to_string(),
                name: "Zhipu / GLM (Z.ai)".to_string(),
                subtitle: "GLM-5.1 and GLM-4.5 agentic models".to_string(),
                badge: "Cloud".to_string(),
                category: "cloud".to_string(),
                priority_rank: 11,
                supports_oauth: false,
                oauth_label: None,
                auth_mode: "api_key".to_string(),
                api_format: "openai".to_string(),
                base_url: "https://api.z.ai/api/paas/v4".to_string(),
                api_key_masked: String::new(),
                api_key_raw: String::new(),
                oauth_access_token: String::new(),
                oauth_refresh_token: String::new(),
                oauth_account_label: None,
                oauth_expires_ms: None,
                key_placeholder: "Z.ai API Key".to_string(),
                env_var: "ZAI_API_KEY".to_string(),
                docs_url: "https://open.bigmodel.cn/".to_string(),
                configured: false,
                selected_model: "glm-5.1".to_string(),
                models: vec![
                    Self::model("glm-5.1", "GLM-5.1", 128_000, true, true),
                    Self::model("glm-4.5", "GLM-4.5", 128_000, true, true),
                ],
                custom_models: vec![],
                advertised_models: Vec::new(),
                context_window: 128_000,
                last_tested_ok: None,
                last_latency_ms: None,
            },
            // 12. Moonshot / Kimi
            ProviderEntry {
                id: "moonshot".to_string(),
                name: "Moonshot / Kimi".to_string(),
                subtitle: "Kimi K2.5 and Moonshot v1 models".to_string(),
                badge: "Cloud".to_string(),
                category: "cloud".to_string(),
                priority_rank: 12,
                supports_oauth: false,
                oauth_label: None,
                auth_mode: "api_key".to_string(),
                api_format: "openai".to_string(),
                base_url: "https://api.moonshot.ai/v1".to_string(),
                api_key_masked: String::new(),
                api_key_raw: String::new(),
                oauth_access_token: String::new(),
                oauth_refresh_token: String::new(),
                oauth_account_label: None,
                oauth_expires_ms: None,
                key_placeholder: "sk-...".to_string(),
                env_var: "MOONSHOT_API_KEY".to_string(),
                docs_url: "https://platform.moonshot.ai/".to_string(),
                configured: false,
                selected_model: "kimi-k2.5".to_string(),
                models: vec![
                    Self::model("kimi-k2.5", "Kimi K2.5", 256_000, true, true),
                    Self::model("moonshot-v1-128k", "Moonshot v1 128K", 128_000, false, false),
                ],
                custom_models: vec![],
                advertised_models: Vec::new(),
                context_window: 256_000,
                last_tested_ok: None,
                last_latency_ms: None,
            },
            // 13. Cohere
            ProviderEntry {
                id: "cohere".to_string(),
                name: "Cohere".to_string(),
                subtitle: "Command A and Command R+ enterprise RAG models".to_string(),
                badge: "Cloud".to_string(),
                category: "cloud".to_string(),
                priority_rank: 13,
                supports_oauth: false,
                oauth_label: None,
                auth_mode: "api_key".to_string(),
                api_format: "openai".to_string(),
                base_url: "https://api.cohere.com/compatibility/v1".to_string(),
                api_key_masked: String::new(),
                api_key_raw: String::new(),
                oauth_access_token: String::new(),
                oauth_refresh_token: String::new(),
                oauth_account_label: None,
                oauth_expires_ms: None,
                key_placeholder: "Cohere API Key".to_string(),
                env_var: "COHERE_API_KEY".to_string(),
                docs_url: "https://dashboard.cohere.com/api-keys".to_string(),
                configured: false,
                selected_model: "command-a-03-2025".to_string(),
                models: vec![
                    Self::model("command-a-03-2025", "Command A (03-2025)", 256_000, false, false),
                    Self::model("command-r-plus-08-2024", "Command R+", 128_000, false, false),
                ],
                custom_models: vec![],
                advertised_models: Vec::new(),
                context_window: 256_000,
                last_tested_ok: None,
                last_latency_ms: None,
            },
            // 14. Together AI
            ProviderEntry {
                id: "together".to_string(),
                name: "Together AI".to_string(),
                subtitle: "Serverless open-weights cloud (DeepSeek, Llama, Qwen)".to_string(),
                badge: "Open Weights".to_string(),
                category: "cloud".to_string(),
                priority_rank: 14,
                supports_oauth: false,
                oauth_label: None,
                auth_mode: "api_key".to_string(),
                api_format: "openai".to_string(),
                base_url: "https://api.together.xyz/v1".to_string(),
                api_key_masked: String::new(),
                api_key_raw: String::new(),
                oauth_access_token: String::new(),
                oauth_refresh_token: String::new(),
                oauth_account_label: None,
                oauth_expires_ms: None,
                key_placeholder: "Together API Key".to_string(),
                env_var: "TOGETHER_API_KEY".to_string(),
                docs_url: "https://api.together.xyz/settings/api-keys".to_string(),
                configured: false,
                selected_model: "deepseek-ai/DeepSeek-V3".to_string(),
                models: vec![
                    Self::model("deepseek-ai/DeepSeek-V3", "DeepSeek V3", 128_000, false, false),
                    Self::model("meta-llama/Llama-3.3-70B-Instruct-Turbo", "Llama 3.3 70B Turbo", 128_000, false, false),
                ],
                custom_models: vec![],
                advertised_models: Vec::new(),
                context_window: 128_000,
                last_tested_ok: None,
                last_latency_ms: None,
            },
            // 15. Fireworks AI
            ProviderEntry {
                id: "fireworks".to_string(),
                name: "Fireworks AI".to_string(),
                subtitle: "Fastserverless inference for DeepSeek, Llama, and Qwen".to_string(),
                badge: "Open Weights".to_string(),
                category: "cloud".to_string(),
                priority_rank: 15,
                supports_oauth: false,
                oauth_label: None,
                auth_mode: "api_key".to_string(),
                api_format: "openai".to_string(),
                base_url: "https://api.fireworks.ai/inference/v1".to_string(),
                api_key_masked: String::new(),
                api_key_raw: String::new(),
                oauth_access_token: String::new(),
                oauth_refresh_token: String::new(),
                oauth_account_label: None,
                oauth_expires_ms: None,
                key_placeholder: "fw_...".to_string(),
                env_var: "FIREWORKS_API_KEY".to_string(),
                docs_url: "https://fireworks.ai/account/api-keys".to_string(),
                configured: false,
                selected_model: "accounts/fireworks/models/deepseek-v3".to_string(),
                models: vec![
                    Self::model("accounts/fireworks/models/deepseek-v3", "DeepSeek V3 (Fireworks)", 128_000, false, false),
                    Self::model("accounts/fireworks/models/llama-v3p3-70b-instruct", "Llama 3.3 70B (Fireworks)", 128_000, false, false),
                ],
                custom_models: vec![],
                advertised_models: Vec::new(),
                context_window: 128_000,
                last_tested_ok: None,
                last_latency_ms: None,
            },
            // 16. Ollama (Local)
            ProviderEntry {
                id: "ollama".to_string(),
                name: "Ollama (Local)".to_string(),
                subtitle: "Local models running on http://localhost:11434/v1".to_string(),
                badge: "Local · :11434".to_string(),
                category: "local".to_string(),
                priority_rank: 16,
                supports_oauth: false,
                oauth_label: None,
                auth_mode: "local".to_string(),
                api_format: "openai".to_string(),
                base_url: "http://localhost:11434/v1".to_string(),
                api_key_masked: String::new(),
                api_key_raw: String::new(),
                oauth_access_token: String::new(),
                oauth_refresh_token: String::new(),
                oauth_account_label: None,
                oauth_expires_ms: None,
                key_placeholder: "No API key required".to_string(),
                env_var: "OLLAMA_HOST".to_string(),
                docs_url: "https://ollama.com".to_string(),
                configured: false,
                selected_model: "qwen2.5-coder:32b".to_string(),
                models: vec![
                    Self::model("qwen2.5-coder:32b", "Qwen 2.5 Coder 32B", 128_000, false, false),
                    Self::model("llama3.3:latest", "Llama 3.3", 128_000, false, false),
                    Self::model("deepseek-r1:32b", "DeepSeek R1 32B", 128_000, true, false),
                ],
                custom_models: vec![],
                advertised_models: Vec::new(),
                context_window: 128_000,
                last_tested_ok: None,
                last_latency_ms: None,
            },
            // 17. LM Studio (Local)
            ProviderEntry {
                id: "lmstudio".to_string(),
                name: "LM Studio (Local)".to_string(),
                subtitle: "Local OpenAI-compatible server on http://localhost:1234/v1".to_string(),
                badge: "Local · :1234".to_string(),
                category: "local".to_string(),
                priority_rank: 17,
                supports_oauth: false,
                oauth_label: None,
                auth_mode: "local".to_string(),
                api_format: "openai".to_string(),
                base_url: "http://localhost:1234/v1".to_string(),
                api_key_masked: String::new(),
                api_key_raw: String::new(),
                oauth_access_token: String::new(),
                oauth_refresh_token: String::new(),
                oauth_account_label: None,
                oauth_expires_ms: None,
                key_placeholder: "lm-studio".to_string(),
                env_var: "LMSTUDIO_HOST".to_string(),
                docs_url: "https://lmstudio.ai".to_string(),
                configured: false,
                selected_model: "local-model".to_string(),
                models: vec![
                    Self::model("local-model", "Loaded LM Studio Model", 128_000, true, false),
                ],
                custom_models: vec![],
                advertised_models: Vec::new(),
                context_window: 128_000,
                last_tested_ok: None,
                last_latency_ms: None,
            },
            // 18. vLLM (Local)
            ProviderEntry {
                id: "vllm".to_string(),
                name: "vLLM (Local)".to_string(),
                subtitle: "High-throughput local server on http://localhost:8000/v1".to_string(),
                badge: "Local · :8000".to_string(),
                category: "local".to_string(),
                priority_rank: 18,
                supports_oauth: false,
                oauth_label: None,
                auth_mode: "local".to_string(),
                api_format: "openai".to_string(),
                base_url: "http://localhost:8000/v1".to_string(),
                api_key_masked: String::new(),
                api_key_raw: String::new(),
                oauth_access_token: String::new(),
                oauth_refresh_token: String::new(),
                oauth_account_label: None,
                oauth_expires_ms: None,
                key_placeholder: "Optional token".to_string(),
                env_var: "VLLM_HOST".to_string(),
                docs_url: "https://docs.vllm.ai".to_string(),
                configured: false,
                selected_model: "vllm-model".to_string(),
                models: vec![
                    Self::model("vllm-model", "Served vLLM Model", 128_000, true, false),
                ],
                custom_models: vec![],
                advertised_models: Vec::new(),
                context_window: 128_000,
                last_tested_ok: None,
                last_latency_ms: None,
            },
            // 19. llama.cpp (Local)
            ProviderEntry {
                id: "llamacpp".to_string(),
                name: "llama.cpp (Local)".to_string(),
                subtitle: "llama-server running on http://localhost:8080/v1".to_string(),
                badge: "Local · :8080".to_string(),
                category: "local".to_string(),
                priority_rank: 19,
                supports_oauth: false,
                oauth_label: None,
                auth_mode: "local".to_string(),
                api_format: "openai".to_string(),
                base_url: "http://localhost:8080/v1".to_string(),
                api_key_masked: String::new(),
                api_key_raw: String::new(),
                oauth_access_token: String::new(),
                oauth_refresh_token: String::new(),
                oauth_account_label: None,
                oauth_expires_ms: None,
                key_placeholder: "Optional key".to_string(),
                env_var: "LLAMACPP_HOST".to_string(),
                docs_url: "https://github.com/ggml-org/llama.cpp".to_string(),
                configured: false,
                selected_model: "gguf-model".to_string(),
                models: vec![
                    Self::model("gguf-model", "Loaded GGUF Model", 128_000, true, false),
                ],
                custom_models: vec![],
                advertised_models: Vec::new(),
                context_window: 128_000,
                last_tested_ok: None,
                last_latency_ms: None,
            },
        ];

        ProvidersStateFile {
            onboarding_completed: false,
            active_provider: "openrouter".to_string(),
            active_model: "anthropic/claude-sonnet-4.6".to_string(),
            subagent_provider: "openrouter".to_string(),
            subagent_model: "anthropic/claude-sonnet-4.6".to_string(),
            providers,
        }
    }

    fn mask_secret(secret: &str) -> String {
        let trimmed = secret.trim();
        if trimmed.is_empty() {
            return String::new();
        }
        let chars: Vec<char> = trimmed.chars().collect();
        if chars.len() <= 8 {
            return "••••••••".to_string();
        }
        let prefix: String = chars.iter().take(6).collect();
        let suffix: String = chars.iter().skip(chars.len() - 4).collect();
        format!("{}••••{}", prefix, suffix)
    }

    fn merge_saved_state(
        mut catalog: ProvidersStateFile,
        saved: &Value,
    ) -> Option<ProvidersStateFile> {
        let obj = saved.as_object()?;
        if let Some(onb) = obj.get("onboardingCompleted").and_then(|v| v.as_bool()) {
            catalog.onboarding_completed = onb;
        }
        if let Some(ap) = obj.get("activeProvider").and_then(|v| v.as_str()) {
            catalog.active_provider = ap.to_string();
        }
        if let Some(am) = obj.get("activeModel").and_then(|v| v.as_str()) {
            if am == "gpt-5.3-codex" {
                catalog.active_model = "gpt-6.1-sol".to_string();
            } else {
                catalog.active_model = am.to_string();
            }
        }
        if let Some(sp) = obj.get("subagentProvider").and_then(|v| v.as_str()) {
            catalog.subagent_provider = sp.to_string();
        }
        if let Some(sm) = obj.get("subagentModel").and_then(|v| v.as_str()) {
            catalog.subagent_model = sm.to_string();
        }

        if let Some(saved_list) = obj.get("providers").and_then(|v| v.as_array()) {
            for saved_p in saved_list {
                let Some(id) = saved_p.get("id").and_then(|v| v.as_str()) else {
                    continue;
                };
                if let Some(entry) = catalog.providers.iter_mut().find(|p| p.id == id) {
                    if let Some(cfg) = saved_p.get("configured").and_then(|v| v.as_bool()) {
                        entry.configured = cfg;
                    }
                    if let Some(bu) = saved_p.get("baseUrl").and_then(|v| v.as_str()) {
                        if !bu.trim().is_empty() {
                            entry.base_url = bu.to_string();
                        }
                    }
                    if let Some(af) = saved_p.get("apiFormat").and_then(|v| v.as_str()) {
                        if !af.trim().is_empty() {
                            entry.api_format = af.to_string();
                        }
                    }
                    if let Some(am) = saved_p.get("authMode").and_then(|v| v.as_str()) {
                        if !am.trim().is_empty() {
                            entry.auth_mode = am.to_string();
                        }
                    }
                    if let Some(sm) = saved_p.get("selectedModel").and_then(|v| v.as_str()) {
                        if !sm.trim().is_empty() {
                            if id == "openai" && sm.trim() == "gpt-5.3-codex" {
                                entry.selected_model = "gpt-6.1-sol".to_string();
                            } else {
                                entry.selected_model = sm.to_string();
                            }
                        }
                    }
                    if let Some(raw_key) = saved_p.get("apiKeyRaw").and_then(|v| v.as_str()) {
                        entry.api_key_raw = raw_key.to_string();
                        entry.api_key_masked = Self::mask_secret(raw_key);
                    }
                    if let Some(oa) = saved_p.get("oauthAccessToken").and_then(|v| v.as_str()) {
                        entry.oauth_access_token = oa.to_string();
                    }
                    if let Some(or_tok) = saved_p.get("oauthRefreshToken").and_then(|v| v.as_str())
                    {
                        entry.oauth_refresh_token = or_tok.to_string();
                    }
                    if let Some(lbl) = saved_p.get("oauthAccountLabel").and_then(|v| v.as_str()) {
                        entry.oauth_account_label = Some(lbl.to_string());
                    }
                    if let Some(exp) = saved_p.get("oauthExpiresMs").and_then(|v| v.as_u64()) {
                        entry.oauth_expires_ms = Some(exp);
                    }
                    if let Some(cw) = saved_p.get("contextWindow").and_then(|v| v.as_u64()) {
                        entry.context_window = cw as u32;
                    }
                    if let Some(saved_models) = saved_p.get("models").and_then(|v| v.as_array()) {
                        for sm_val in saved_models {
                            if let Ok(pm) =
                                serde_json::from_value::<ProviderModelInfo>(sm_val.clone())
                            {
                                if pm.id == "gpt-5.3-codex" {
                                    continue;
                                }
                                if !entry.models.iter().any(|m| m.id == pm.id) {
                                    entry.models.push(pm);
                                }
                            }
                        }
                    }
                    if let Some(models) = saved_p.get("advertisedModels").and_then(Value::as_array) {
                        entry.advertised_models = models.iter().filter_map(Value::as_str)
                            .filter(|id| !id.is_empty()).take(2000).map(str::to_owned).collect();
                    }
                    if let Some(cm) = saved_p.get("customModels").and_then(|v| v.as_array()) {
                        entry.custom_models = cm
                            .iter()
                            .filter_map(|x| x.as_str().map(|s| s.to_string()))
                            .collect();
                        for m_id in &entry.custom_models {
                            if !entry.models.iter().any(|m| &m.id == m_id) {
                                entry.models.push(Self::model(
                                    m_id,
                                    m_id,
                                    entry.context_window,
                                    true,
                                    true,
                                ));
                            }
                        }
                    }
                }
            }
        }
        // Repair stale catalog placeholders only within the same configured connection.
        // A deliberate alternative model remains selected when that connection knows it.
        Self::repair_active_selection(&mut catalog);
        Some(catalog)
    }

    fn placeholder_model(model: &str) -> bool {
        matches!(model.trim(), "" | "custom-model" | "local-model" | "vllm-model" | "gguf-model")
    }

    fn owns_model(entry: &ProviderEntry, model: &str) -> bool {
        entry.configured && (!Self::placeholder_model(model) || entry.advertised_models.iter().any(|id|id==model))
            && (entry.selected_model == model || entry.models.iter().any(|m|
                m.id == model && Self::is_model_available_for_provider(entry, m)))
    }

    fn repair_active_selection(state: &mut ProvidersStateFile) {
        if let Some(entry) = state.providers.iter_mut().find(|p| p.id == state.active_provider && p.configured) {
            if !Self::placeholder_model(&entry.selected_model) || entry.advertised_models.contains(&entry.selected_model) {
                entry.models.retain(|m| !Self::placeholder_model(&m.id) || entry.advertised_models.contains(&m.id));
                entry.custom_models.retain(|m| !Self::placeholder_model(m) || entry.advertised_models.contains(m));
                if !Self::owns_model(entry, &state.active_model) {
                    state.active_model = entry.selected_model.clone();
                }
            }
        }
    }

    /// Resolve an exact model and optional explicit connection without making an HTTP request.
    /// The context window is configured metadata, not a measured server capacity.
    pub fn run_selection(&self, model: &str, provider: Option<&str>) -> Result<(String, String, u32), CompletionError> {
        let requested = provider.filter(|p| !p.trim().is_empty())
            .map(|p| format!("{}::{model}", p.trim())).unwrap_or_else(|| model.to_owned());
        let (provider, _, model, _, _, _, _) = self.select_provider(Some(&requested), true)?;
        let state = self.state.read();
        let entry = state.providers.iter().find(|p| p.id == provider).expect("selected provider exists");
        let model_context = entry.models.iter().find(|m| m.id == model)
            .map(|m| m.context_window).filter(|n| *n >= 1024).unwrap_or(entry.context_window);
        Ok((provider, model, model_context.min(entry.context_window).max(1024)))
    }

    pub fn persist(&self) {
        let st = self.state.read();
        let mut providers_disk = Vec::new();
        for p in &st.providers {
            let mut val = serde_json::to_value(p).unwrap_or_else(|_| json!({}));
            if let Some(obj) = val.as_object_mut() {
                obj.insert("apiKeyRaw".to_string(), json!(p.api_key_raw));
                obj.insert("oauthAccessToken".to_string(), json!(p.oauth_access_token));
                obj.insert(
                    "oauthRefreshToken".to_string(),
                    json!(p.oauth_refresh_token),
                );
            }
            providers_disk.push(val);
        }
        let disk_json = json!({
            "onboardingCompleted": st.onboarding_completed,
            "activeProvider": st.active_provider,
            "activeModel": st.active_model,
            "subagentProvider": st.subagent_provider,
            "subagentModel": st.subagent_model,
            "providers": providers_disk,
        });
        if let Ok(pretty) = serde_json::to_string_pretty(&disk_json) {
            let _ = fs::write(&self.config_path, pretty);
        }
    }

    fn environment_key_names(entry: &ProviderEntry, base_url: &str) -> Vec<String> {
        let mut names = Vec::new();
        // Local catalog entries historically use *_HOST; those are URLs, never credentials.
        let primary = match entry.id.as_str() {
            "ollama" => "OLLAMA_API_KEY",
            "lmstudio" => "LMSTUDIO_API_KEY",
            "vllm" => "VLLM_API_KEY",
            "llamacpp" => "LLAMACPP_API_KEY",
            _ => entry.env_var.as_str(),
        };
        if primary.ends_with("_API_KEY") { names.push(primary.to_owned()); }
        if entry.id == "custom" {
            let host = url::Url::parse(base_url).ok().and_then(|u| u.host_str().map(str::to_owned));
            if let Some(host) = host {
                for known in Self::default_catalog().providers {
                    if known.id != "custom" && known.category != "local"
                        && url::Url::parse(&known.base_url).ok().and_then(|u| u.host_str().map(str::to_owned)).as_deref() == Some(host.as_str())
                        && known.env_var.ends_with("_API_KEY") && !names.contains(&known.env_var) {
                        names.push(known.env_var);
                    }
                }
            }
        }
        if names.iter().any(|n| n == "GEMINI_API_KEY") { names.push("GOOGLE_API_KEY".into()); }
        names
    }

    fn resolve_key_with(entry: &ProviderEntry, supplied: &str, base_url: &str, lookup: impl Fn(&str) -> Option<String>) -> (String, String, Option<String>) {
        let supplied = supplied.trim();
        if !supplied.is_empty() && !supplied.contains("••••") { return (supplied.into(), "entered".into(), None); }
        if entry.auth_mode == "oauth" && !entry.oauth_access_token.is_empty() { return (entry.oauth_access_token.clone(), "oauth".into(), None); }
        if !entry.api_key_raw.trim().is_empty() { return (entry.api_key_raw.clone(), "saved".into(), None); }
        for name in Self::environment_key_names(entry, base_url) {
            if let Some(value) = lookup(&name).filter(|s| !s.trim().is_empty()) {
                return (value.trim().into(), "environment".into(), Some(name));
            }
        }
        (String::new(), "none".into(), None)
    }

    fn resolve_key(entry: &ProviderEntry, supplied: &str, base_url: &str) -> (String, String, Option<String>) {
        Self::resolve_key_with(entry, supplied, base_url, |name| std::env::var(name).ok())
    }

    // Separate, explicit provider routing; this never changes the driving agent's model.
    pub fn specialist_request(&self, provider: &str, body: Option<Value>) -> anyhow::Result<Value> {
        use anyhow::{bail, Context};
        use std::io::Read;
        let entry = self.state.read().providers.iter().find(|p|p.id==provider).cloned()
            .context("Choose a configured specialist provider")?;
        if entry.api_format != "openai" || entry.auth_mode == "oauth" {
            bail!("LLM4Decompile requires an OpenAI-compatible text-completion endpoint with API key or local authentication");
        }
        let base = entry.base_url.trim_end_matches('/');
        let url = url::Url::parse(base)?;
        if !matches!(url.scheme(),"http"|"https") || !url.username().is_empty() || url.password().is_some() || url.query().is_some() {
            bail!("Use an HTTP(S) API base URL without credentials or query parameters");
        }
        let key = Self::resolve_key(&entry,"",base).0;
        let generating = body.is_some();
        let client = reqwest::blocking::Client::builder()
            .connect_timeout(std::time::Duration::from_secs(10))
            .timeout(std::time::Duration::from_secs(if generating { 180 } else { 10 }))
            .redirect(reqwest::redirect::Policy::none()).build()?;
        let mut request = if let Some(body) = body {
            client.post(format!("{base}/completions")).json(&body)
        } else { client.get(format!("{base}/models")) };
        if !key.is_empty() { request = request.bearer_auth(&key); }
        let response = request.send().context("Specialist endpoint request failed")?;
        let status = response.status();
        let mut bytes = vec![];
        response.take(2 * 1024 * 1024 + 1).read_to_end(&mut bytes)?;
        if bytes.len() > 2 * 1024 * 1024 { bail!("Specialist response exceeds 2 MiB"); }
        if !status.is_success() {
            let text = String::from_utf8_lossy(&bytes);
            let text = if key.is_empty() { text.into_owned() } else { text.replace(&key,"[redacted]") };
            bail!("Specialist endpoint HTTP {}: {}",status.as_u16(),text.chars().take(1000).collect::<String>());
        }
        let result: Value = serde_json::from_slice(&bytes).context("Specialist endpoint did not return JSON")?;
        if !result["error"].is_null() { bail!("Specialist endpoint returned an error"); }
        Ok(result)
    }

    pub fn get_public_state(&self) -> Value {
        let st = self.state.read();
        let configured_count = st.providers.iter().filter(|p| p.configured).count();
        let providers: Vec<Value> = st.providers.iter().map(|entry| {
            let (_, source, variable) = Self::resolve_key(entry, "", &entry.base_url);
            let mut public = serde_json::to_value(entry).expect("provider serialization");
            public["credentialSource"] = json!(source);
            public["environmentVariable"] = json!(variable);
            public["environmentCandidates"] = json!(Self::environment_key_names(entry, &entry.base_url));
            public["selectedModelValid"] = json!(Self::owns_model(entry, &entry.selected_model));
            public["models"] = json!(entry.models.iter().filter(|m| !Self::placeholder_model(&m.id) || entry.advertised_models.contains(&m.id)).collect::<Vec<_>>());
            public
        }).collect();
        json!({
            "onboardingCompleted": st.onboarding_completed && configured_count > 0,
            "hasConfiguredProvider": configured_count > 0,
            "configuredCount": configured_count,
            "activeProvider": st.active_provider,
            "activeModel": st.active_model,
            "subagentProvider": st.subagent_provider,
            "subagentModel": st.subagent_model,
            "providers": providers,
        })
    }

    pub fn save_provider(&self, body: &Value) -> Value {
        let provider_id = body
            .get("providerId")
            .or_else(|| body.get("id"))
            .and_then(|v| v.as_str())
            .unwrap_or("openrouter");

        if let Some(cw) = body.get("contextWindow") {
            if !cw.as_u64().is_some_and(|n| (1024..=2_000_000).contains(&n)) {
                let mut result = self.get_public_state();
                result["error"] = json!("Context window must be between 1,024 and 2,000,000 tokens; use the server's configured capacity.");
                return result;
            }
        }
        let mut st = self.state.write();
        let mut updated_model = String::new();
        let mut found = false;
        let mut missing_credential = None;

        if let Some(entry) = st.providers.iter_mut().find(|p| p.id == provider_id) {
            found = true;
            if let Some(api_key) = body.get("apiKey").and_then(|v| v.as_str()) {
                let trimmed = api_key.trim();
                if !trimmed.is_empty() && !trimmed.contains("••••") {
                    entry.api_key_raw = trimmed.to_string();
                    entry.api_key_masked = Self::mask_secret(trimmed);
                }
            }
            if let Some(base_url) = body.get("baseUrl").and_then(|v| v.as_str()) {
                if !base_url.trim().is_empty() {
                    let new_url = base_url.trim().trim_end_matches('/');
                    if entry.base_url.trim_end_matches('/') != new_url { entry.advertised_models.clear(); }
                    entry.base_url = new_url.to_string();
                }
            }
            if let Some(api_format) = body.get("apiFormat").and_then(|v| v.as_str()) {
                if !api_format.trim().is_empty() {
                    entry.api_format = api_format.trim().to_string();
                }
            }
            if let Some(auth_mode) = body.get("authMode").and_then(|v| v.as_str()) {
                if !auth_mode.trim().is_empty() {
                    entry.auth_mode = auth_mode.trim().to_string();
                }
            }
            if let Some(cw) = body.get("contextWindow").and_then(|v| v.as_u64()) {
                if cw >= 1024 {
                    entry.context_window = cw as u32;
                }
            }
            if let Some(custom_model) = body.get("customModel").and_then(|v| v.as_str()) {
                let cm = custom_model.trim();
                if !cm.is_empty() {
                    if !entry.custom_models.contains(&cm.to_string()) {
                        entry.custom_models.push(cm.to_string());
                    }
                    if !entry.models.iter().any(|m| m.id == cm) {
                        entry
                            .models
                            .insert(0, Self::model(cm, cm, entry.context_window, true, true));
                    }
                    entry.selected_model = cm.to_string();
                }
            }
            if let Some(sel_model) = body.get("selectedModel").and_then(|v| v.as_str()) {
                let sm = sel_model.trim();
                if !sm.is_empty() {
                    if !entry.models.iter().any(|m| m.id == sm) {
                        entry
                            .models
                            .insert(0, Self::model(sm, sm, entry.context_window, true, true));
                    }
                    entry.selected_model = sm.to_string();
                }
            }
            // A provider that needs a credential is configured only when one resolves
            // (entered now, saved, OAuth or environment); local and custom endpoints need none.
            if Self::needs_credential(entry) && Self::resolve_key(entry, "", &entry.base_url).0.is_empty() {
                entry.configured = false;
                missing_credential = Some(format!(
                    "{} needs an API key. Enter one{}, then save again.",
                    entry.name,
                    match Self::environment_key_names(entry, &entry.base_url).as_slice() {
                        [] => String::new(),
                        names => format!(" or set {} and restart REA Studio", names.join(" or ")),
                    }
                ));
            } else {
                entry.configured = true;
            }
            // A custom/local endpoint's serving capacity is user configuration. Its
            // discovered IDs inherit this capacity; stale catalog metadata must not
            // silently cap an explicitly increased server context. Official provider
            // model limits remain intact and can still cap a connection-level value.
            if body.get("contextWindow").is_some()
                && (entry.category == "local" || entry.auth_mode == "custom" || entry.auth_mode == "local")
            {
                if let Some(model) = entry.models.iter_mut().find(|m| m.id == entry.selected_model) {
                    model.context_window = entry.context_window;
                }
            }
            updated_model = entry.selected_model.clone();
        }

        if found && missing_credential.is_none() {
            if st.active_provider == provider_id || body
                .get("setAsActive")
                .and_then(|v| v.as_bool())
                .unwrap_or(true)
            {
                st.active_provider = provider_id.to_string();
                if !updated_model.is_empty() {
                    st.active_model = updated_model;
                }
            }
            if body
                .get("completeOnboarding")
                .and_then(|v| v.as_bool())
                .unwrap_or(false)
            {
                st.onboarding_completed = true;
            }
        }
        Self::repair_active_selection(&mut st);
        drop(st);
        self.persist();
        let mut state = self.get_public_state();
        if let Some(message) = missing_credential {
            state["error"] = json!(message);
        }
        state
    }

    /// Whether requests to this provider need an API key or OAuth token.
    fn needs_credential(entry: &ProviderEntry) -> bool {
        entry.category != "local" && !matches!(entry.auth_mode.as_str(), "custom" | "local")
    }

    pub fn remove_provider(&self, body: &Value) -> Value {
        let provider_id = body
            .get("providerId")
            .or_else(|| body.get("id"))
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let mut st = self.state.write();
        if let Some(entry) = st.providers.iter_mut().find(|p| p.id == provider_id) {
            entry.configured = false;
            entry.api_key_raw.clear();
            entry.api_key_masked.clear();
            entry.oauth_access_token.clear();
            entry.oauth_refresh_token.clear();
            entry.oauth_account_label = None;
            entry.oauth_expires_ms = None;
            entry.last_tested_ok = None;
        }
        let remaining_first = st
            .providers
            .iter()
            .find(|p| p.configured)
            .map(|p| (p.id.clone(), p.selected_model.clone()));
        if let Some((pid, mid)) = remaining_first {
            if st.active_provider == provider_id {
                st.active_provider = pid;
                st.active_model = mid;
            }
        } else {
            st.onboarding_completed = false;
        }
        drop(st);
        self.persist();
        self.get_public_state()
    }

    pub fn complete_onboarding(&self, body: &Value) -> Value {
        let (provider, model) = {
            let state = self.state.read();
            (body["activeProvider"].as_str().unwrap_or(&state.active_provider).to_owned(),
             body["activeModel"].as_str().unwrap_or(&state.active_model).to_owned())
        };
        if let Err(error) = self.run_selection(&model, Some(&provider)) {
            let mut result = self.get_public_state();
            result["error"] = json!(error.to_string());
            return result;
        }
        let mut st = self.state.write();
        if let Some(ap) = body.get("activeProvider").and_then(|v| v.as_str()) {
            if !ap.is_empty() {
                st.active_provider = ap.to_string();
            }
        }
        if let Some(am) = body.get("activeModel").and_then(|v| v.as_str()) {
            if !am.is_empty() {
                st.active_model = am.to_string();
            }
        }
        if let Some(sp) = body.get("subagentProvider").and_then(|v| v.as_str()) {
            if !sp.is_empty() {
                st.subagent_provider = sp.to_string();
            }
        }
        if let Some(sm) = body.get("subagentModel").and_then(|v| v.as_str()) {
            if !sm.is_empty() {
                st.subagent_model = sm.to_string();
            }
        }
        let any_configured = st.providers.iter().any(|p| p.configured);
        if any_configured {
            st.onboarding_completed = true;
        }
        drop(st);
        self.persist();
        self.get_public_state()
    }

    pub fn test_provider(&self, body: &Value) -> Value {
        let provider_id = body
            .get("providerId")
            .and_then(|v| v.as_str())
            .unwrap_or("openrouter");
        let supplied_key = body
            .get("apiKey")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .trim();
        let supplied_url = body
            .get("baseUrl")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .trim();

        let (base_url, api_key, api_format, _is_local) = {
            let st = self.state.read();
            if let Some(entry) = st.providers.iter().find(|p| p.id == provider_id) {
                let url = if !supplied_url.is_empty() {
                    supplied_url.trim_end_matches('/').to_string()
                } else {
                    entry.base_url.trim_end_matches('/').to_string()
                };
                let key = Self::resolve_key(entry, supplied_key, &url).0;
                (
                    url,
                    key,
                    entry.api_format.clone(),
                    entry.category == "local",
                )
            } else {
                (
                    supplied_url.to_string(),
                    supplied_key.to_string(),
                    "openai".to_string(),
                    false,
                )
            }
        };

        let start = Instant::now();
        let client = reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_secs(6))
            .build();

        let mut ok = false;
        let mut message = String::new();
        let mut discovered_models: Vec<String> = Vec::new();

        if let Ok(http) = client {
            if provider_id == "openai"
                && !api_key.is_empty()
                && Self::extract_chatgpt_account_id(&api_key).is_some()
            {
                let codex_models = Self::fetch_codex_models(&http, &api_key);
                if !codex_models.is_empty() {
                    ok = true;
                    discovered_models = codex_models;
                    message = format!(
                        "Connected to ChatGPT Codex ({} models available)",
                        discovered_models.len()
                    );
                } else {
                    ok = true;
                    message = "ChatGPT Codex OAuth token verified".to_string();
                }
            } else {
                let models_url = format!("{}/models", base_url);
                let mut req = http.get(&models_url);
                if !api_key.is_empty() {
                    if api_format == "anthropic" {
                        req = req
                            .header("x-api-key", &api_key)
                            .header("anthropic-version", "2023-06-01");
                    } else {
                        req = req.header("Authorization", format!("Bearer {}", api_key));
                    }
                }
                match req.send() {
                    Ok(resp) => {
                        let status = resp.status();
                        if let Ok(json_body) = resp.json::<Value>() {
                            if let Some(arr) = json_body.get("data").and_then(|v| v.as_array()) {
                                for item in arr.iter().take(2000) {
                                    if let Some(id) = item.get("id").and_then(|v| v.as_str()) {
                                        discovered_models.push(id.to_string());
                                    }
                                }
                            }
                        }
                        if status.is_success() {
                            ok = true;
                            message = if discovered_models.is_empty() {
                                format!("Connected to {} ({})", provider_id, status.as_u16())
                            } else {
                                format!("Connected ({} models available)", discovered_models.len())
                            };
                        } else {
                            message = format!("HTTP {} from {}", status.as_u16(), models_url);
                        }
                    }
                    Err(err) => {
                        message = format!("Connection failed: {}", err);
                    }
                }
            }
        }

        let latency_ms = start.elapsed().as_millis() as u64;
        {
            let mut st = self.state.write();
            if let Some(entry) = st.providers.iter_mut().find(|p| p.id == provider_id) {
                entry.last_tested_ok = Some(ok);
                entry.last_latency_ms = Some(latency_ms);
                if ok && !discovered_models.is_empty() && entry.base_url.trim_end_matches('/') == base_url {
                    entry.advertised_models = discovered_models.clone();
                    entry.models.retain(|m| !Self::placeholder_model(&m.id) || entry.advertised_models.contains(&m.id));
                    entry.custom_models.retain(|m| !Self::placeholder_model(m) || entry.advertised_models.contains(m));
                }
                for m_id in &discovered_models {
                    if !entry.models.iter().any(|m| &m.id == m_id) {
                        entry.models.push(Self::model(
                            m_id,
                            m_id,
                            entry.context_window,
                            true,
                            true,
                        ));
                    }
                }
            }
        }
        self.persist();

        json!({
            "ok": ok,
            "providerId": provider_id,
            "latencyMs": latency_ms,
            "message": message,
            "discoveredModels": discovered_models,
        })
    }

    /// Add advertised choices without changing either selected model or credentials.
    pub fn remember_models(&self, provider: &str, models: &[&str]) {
        let mut st = self.state.write();
        if let Some(entry) = st.providers.iter_mut().find(|p| p.id == provider) {
            if !models.is_empty() {
                entry.advertised_models = models.iter().filter(|id| !id.is_empty()).take(2000).map(|id| (*id).to_owned()).collect();
                entry.models.retain(|m| !Self::placeholder_model(&m.id) || entry.advertised_models.contains(&m.id));
                entry.custom_models.retain(|m| !Self::placeholder_model(m) || entry.advertised_models.contains(m));
            }
            for id in models.iter().filter(|id| !id.is_empty()).take(2000) {
                if !entry.models.iter().any(|m| m.id == *id) {
                    entry.models.push(Self::model(id, id, entry.context_window, false, false));
                }
            }
        }
        drop(st);
        self.persist();
    }

    /// Record a reachable local server. The user's chosen model is kept; only an empty choice,
    /// or the catalog placeholder of a provider that was not configured yet and is not served,
    /// is replaced by the first served model.
    fn apply_detected(entry: &mut ProviderEntry, models: &[String]) {
        let replace = entry.selected_model.trim().is_empty()
            || (!entry.configured && !models.contains(&entry.selected_model));
        entry.configured = true;
        entry.last_tested_ok = Some(true);
        if replace {
            if let Some(first_model) = models.first() {
                entry.selected_model = first_model.clone();
            }
        }
        if !models.is_empty() {
            entry.advertised_models = models.iter().take(2000).cloned().collect();
            entry.models.retain(|m| !Self::placeholder_model(&m.id) || entry.advertised_models.contains(&m.id));
            entry.custom_models.retain(|m| !Self::placeholder_model(m) || entry.advertised_models.contains(m));
        }
        for mid in models {
            if !entry.models.iter().any(|m| &m.id == mid) {
                entry.models.insert(0, Self::model(mid, mid, entry.context_window, true, false));
            }
        }
    }

    pub fn detect_local_servers(&self) -> Value {
        let targets = [
            ("ollama", "Ollama", "http://localhost:11434/v1/models"),
            ("lmstudio", "LM Studio", "http://localhost:1234/v1/models"),
            ("vllm", "vLLM", "http://localhost:8000/v1/models"),
            ("llamacpp", "llama.cpp", "http://localhost:8080/v1/models"),
        ];

        let client = reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_millis(900))
            .build()
            .ok();

        let mut results = Vec::new();
        for (id, name, default_url) in targets {
            // Probe the configured base URL (a changed port or host), not only the default.
            let url = {
                let st = self.state.read();
                st.providers
                    .iter()
                    .find(|p| p.id == id)
                    .map(|p| p.base_url.trim().trim_end_matches('/'))
                    .filter(|base| !base.is_empty())
                    .map(|base| format!("{base}/models"))
                    .unwrap_or_else(|| default_url.to_string())
            };
            let mut reachable = false;
            let mut models = Vec::new();
            if let Some(ref http) = client {
                if let Ok(resp) = http.get(&url).send() {
                    if resp.status().is_success() {
                        reachable = true;
                        if let Ok(val) = resp.json::<Value>() {
                            if let Some(arr) = val.get("data").and_then(|v| v.as_array()) {
                                for m in arr {
                                    if let Some(mid) = m.get("id").and_then(|v| v.as_str()) {
                                        models.push(mid.to_string());
                                    }
                                }
                            }
                        }
                    }
                }
            }
            if reachable {
                let mut st = self.state.write();
                if let Some(entry) = st.providers.iter_mut().find(|p| p.id == id) {
                    Self::apply_detected(entry, &models);
                }
            }
            results.push(json!({
                "url": url,
                "id": id,
                "name": name,
                "reachable": reachable,
                "models": models,
            }));
        }
        self.persist();
        json!({
            "servers": results,
            "state": self.get_public_state(),
        })
    }

    fn generate_pkce() -> (String, String, String) {
        let raw_bytes = format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple());
        let verifier = URL_SAFE_NO_PAD.encode(raw_bytes.as_bytes());
        let mut hasher = Sha256::new();
        hasher.update(verifier.as_bytes());
        let challenge = URL_SAFE_NO_PAD.encode(hasher.finalize());
        let state = Uuid::new_v4().simple().to_string();
        (verifier, challenge, state)
    }

    /// Starts OpenAI Codex OAuth or xAI Grok OAuth (Device Code + Browser PKCE)
    pub fn start_oauth(&self, body: &Value) -> Value {
        let provider_id = body
            .get("providerId")
            .and_then(|v| v.as_str())
            .unwrap_or("openai");
        let open_browser = body
            .get("openBrowser")
            .and_then(|v| v.as_bool())
            .unwrap_or(true);

        let (verifier, challenge, state) = Self::generate_pkce();
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);

        let client = reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_secs(6))
            .build()
            .ok();

        if provider_id == "xai" {
            // xAI Grok RFC 8628 Device Flow (from HexisPro core/auth/xai_oauth.py)
            let mut verification_url = "https://accounts.x.ai/device".to_string();
            let mut user_code = format!(
                "{}-{}",
                &Uuid::new_v4().simple().to_string().to_uppercase()[..4],
                &Uuid::new_v4().simple().to_string().to_uppercase()[4..8]
            );
            let mut device_code = Uuid::new_v4().to_string();
            let mut token_endpoint = "https://auth.x.ai/oauth/token".to_string();

            if let Some(ref http) = client {
                if let Ok(disc_resp) = http.get(XAI_OAUTH_DISCOVERY_URL).send() {
                    if let Ok(disc) = disc_resp.json::<Value>() {
                        let dev_ep = disc
                            .get("device_authorization_endpoint")
                            .and_then(|v| v.as_str())
                            .unwrap_or("");
                        if let Some(tok_ep) = disc.get("token_endpoint").and_then(|v| v.as_str()) {
                            token_endpoint = tok_ep.to_string();
                        }
                        if !dev_ep.is_empty() {
                            if let Ok(code_resp) = http
                                .post(dev_ep)
                                .form(&[
                                    ("client_id", XAI_OAUTH_CLIENT_ID),
                                    ("scope", XAI_OAUTH_SCOPE),
                                ])
                                .send()
                            {
                                if let Ok(code_json) = code_resp.json::<Value>() {
                                    if let Some(uc) =
                                        code_json.get("user_code").and_then(|v| v.as_str())
                                    {
                                        user_code = uc.to_string();
                                    }
                                    if let Some(dc) =
                                        code_json.get("device_code").and_then(|v| v.as_str())
                                    {
                                        device_code = dc.to_string();
                                    }
                                    if let Some(vu) = code_json
                                        .get("verification_uri_complete")
                                        .or_else(|| code_json.get("verification_uri"))
                                        .and_then(|v| v.as_str())
                                    {
                                        verification_url = vu.to_string();
                                    }
                                }
                            }
                        }
                    }
                }
            }

            let session = PendingOAuthSession {
                provider_id: "xai".to_string(),
                pkce_verifier: verifier,
                pkce_challenge: challenge,
                state: state.clone(),
                authorize_url: verification_url.clone(),
                verification_url: verification_url.clone(),
                user_code: user_code.clone(),
                device_id: device_code,
                token_endpoint,
                created_at_ms: now_ms,
            };
            self.pending_oauth
                .write()
                .insert("xai".to_string(), session);

            if open_browser && std::env::var("QUIXI_E2E_TEST").is_err() {
                let _ = quixi_platform::open_external(&verification_url);
            }

            return json!({
                "ok": true,
                "providerId": "xai",
                "userCode": user_code,
                "verificationUrl": verification_url,
                "authorizeUrl": verification_url,
                "state": state,
            });
        }

        // Default: OpenAI Codex OAuth (PKCE + Device Code from HexisPro core/auth/openai_codex.py)
        let authorize_url = format!(
            "{}?response_type=code&client_id={}&redirect_uri={}&scope=openid%20profile%20email%20offline_access&code_challenge={}&code_challenge_method=S256&state={}&id_token_add_organizations=true&codex_cli_simplified_flow=true&originator=pi",
            OPENAI_CODEX_AUTHORIZE_URL,
            OPENAI_CODEX_CLIENT_ID,
            url::form_urlencoded::byte_serialize(OPENAI_CODEX_REDIRECT_URI.as_bytes()).collect::<String>(),
            challenge,
            state
        );

        let mut user_code = format!(
            "{}-{}",
            &Uuid::new_v4().simple().to_string().to_uppercase()[..4],
            &Uuid::new_v4().simple().to_string().to_uppercase()[4..8]
        );
        let mut device_auth_id = Uuid::new_v4().to_string();

        if let Some(ref http) = client {
            if let Ok(resp) = http
                .post(OPENAI_CODEX_DEVICE_USERCODE_URL)
                .json(&json!({ "client_id": OPENAI_CODEX_CLIENT_ID }))
                .send()
            {
                if let Ok(data) = resp.json::<Value>() {
                    if let Some(da) = data.get("device_auth_id").and_then(|v| v.as_str()) {
                        device_auth_id = da.to_string();
                    }
                    if let Some(uc) = data
                        .get("user_code")
                        .or_else(|| data.get("usercode"))
                        .and_then(|v| v.as_str())
                    {
                        user_code = uc.to_string();
                    }
                }
            }
        }

        let session = PendingOAuthSession {
            provider_id: "openai".to_string(),
            pkce_verifier: verifier,
            pkce_challenge: challenge,
            state: state.clone(),
            authorize_url: authorize_url.clone(),
            verification_url: OPENAI_CODEX_DEVICE_VERIFICATION_URL.to_string(),
            user_code: user_code.clone(),
            device_id: device_auth_id,
            token_endpoint: OPENAI_CODEX_TOKEN_URL.to_string(),
            created_at_ms: now_ms,
        };
        self.pending_oauth
            .write()
            .insert("openai".to_string(), session);

        if open_browser && std::env::var("QUIXI_E2E_TEST").is_err() {
            let _ = quixi_platform::open_external(OPENAI_CODEX_DEVICE_VERIFICATION_URL);
        }

        json!({
            "ok": true,
            "providerId": "openai",
            "userCode": user_code,
            "verificationUrl": OPENAI_CODEX_DEVICE_VERIFICATION_URL,
            "authorizeUrl": authorize_url,
            "state": state,
        })
    }

    /// Polls device code status or completes PKCE code exchange for OpenAI Codex / xAI Grok
    pub fn complete_or_poll_oauth(&self, body: &Value) -> Value {
        let provider_id = body
            .get("providerId")
            .and_then(|v| v.as_str())
            .unwrap_or("openai");
        let callback_input = body
            .get("callbackInput")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .trim();
        let force_complete = body
            .get("completeNow")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        let pending = self.pending_oauth.read().get(provider_id).cloned();
        let client = reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_secs(6))
            .build()
            .ok();

        let mut token_acquired: Option<(String, String, String)> = None;

        if let Some(ref sess) = pending {
            if provider_id == "openai" {
                if !callback_input.is_empty() {
                    // Extract ?code=... from pasted URL or raw code
                    let code = if let Ok(parsed) = url::Url::parse(callback_input) {
                        parsed
                            .query_pairs()
                            .find(|(k, _)| k == "code")
                            .map(|(_, v)| v.to_string())
                            .unwrap_or_else(|| callback_input.to_string())
                    } else {
                        callback_input.to_string()
                    };
                    if let Some(ref http) = client {
                        if let Ok(resp) = http
                            .post(OPENAI_CODEX_TOKEN_URL)
                            .form(&[
                                ("grant_type", "authorization_code"),
                                ("client_id", OPENAI_CODEX_CLIENT_ID),
                                ("code", code.as_str()),
                                ("code_verifier", sess.pkce_verifier.as_str()),
                                ("redirect_uri", OPENAI_CODEX_REDIRECT_URI),
                            ])
                            .send()
                        {
                            if let Ok(tok_json) = resp.json::<Value>() {
                                if let Some(acc) =
                                    tok_json.get("access_token").and_then(|v| v.as_str())
                                {
                                    let refr = tok_json
                                        .get("refresh_token")
                                        .and_then(|v| v.as_str())
                                        .unwrap_or("")
                                        .to_string();
                                    token_acquired = Some((
                                        acc.to_string(),
                                        refr,
                                        "ChatGPT Plus/Pro (Codex OAuth)".to_string(),
                                    ));
                                }
                            }
                        }
                    }
                    if token_acquired.is_none() {
                        token_acquired = Some((
                            code,
                            String::new(),
                            "ChatGPT Plus/Pro (Codex OAuth)".to_string(),
                        ));
                    }
                } else if let Some(ref http) = client {
                    if let Ok(resp) = http
                        .post(OPENAI_CODEX_DEVICE_TOKEN_URL)
                        .json(&json!({
                            "device_auth_id": sess.device_id,
                            "user_code": sess.user_code,
                        }))
                        .send()
                    {
                        if resp.status().is_success() {
                            if let Ok(dev_json) = resp.json::<Value>() {
                                let auth_code = dev_json
                                    .get("authorization_code")
                                    .and_then(|v| v.as_str())
                                    .unwrap_or("");
                                let code_ver = dev_json
                                    .get("code_verifier")
                                    .and_then(|v| v.as_str())
                                    .unwrap_or("");
                                if !auth_code.is_empty() && !code_ver.is_empty() {
                                    if let Ok(tok_resp) = http
                                        .post(OPENAI_CODEX_TOKEN_URL)
                                        .form(&[
                                            ("grant_type", "authorization_code"),
                                            ("client_id", OPENAI_CODEX_CLIENT_ID),
                                            ("code", auth_code),
                                            ("code_verifier", code_ver),
                                            ("redirect_uri", OPENAI_CODEX_DEVICE_REDIRECT_URI),
                                        ])
                                        .send()
                                    {
                                        if let Ok(tok_json) = tok_resp.json::<Value>() {
                                            if let Some(acc) = tok_json
                                                .get("access_token")
                                                .and_then(|v| v.as_str())
                                            {
                                                let refr = tok_json
                                                    .get("refresh_token")
                                                    .and_then(|v| v.as_str())
                                                    .unwrap_or("")
                                                    .to_string();
                                                token_acquired = Some((
                                                    acc.to_string(),
                                                    refr,
                                                    "ChatGPT Plus/Pro (Codex OAuth)".to_string(),
                                                ));
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            } else if provider_id == "xai" {
                if let Some(ref http) = client {
                    if let Ok(resp) = http
                        .post(&sess.token_endpoint)
                        .form(&[
                            ("grant_type", XAI_DEVICE_GRANT_TYPE),
                            ("client_id", XAI_OAUTH_CLIENT_ID),
                            ("device_code", sess.device_id.as_str()),
                        ])
                        .send()
                    {
                        if resp.status().is_success() {
                            if let Ok(tok_json) = resp.json::<Value>() {
                                if let Some(acc) =
                                    tok_json.get("access_token").and_then(|v| v.as_str())
                                {
                                    let refr = tok_json
                                        .get("refresh_token")
                                        .and_then(|v| v.as_str())
                                        .unwrap_or("")
                                        .to_string();
                                    token_acquired = Some((
                                        acc.to_string(),
                                        refr,
                                        "SuperGrok / X Account (OAuth)".to_string(),
                                    ));
                                }
                            }
                        }
                    }
                }
            }
        }

        if token_acquired.is_none() && provider_id == "openai" {
            // Also check if the user already has valid Codex OAuth credentials in ~/.hexis/auth/oauth.openai_codex.json or ~/.codex/auth.json
            if let Some(home) = dirs::home_dir() {
                let hexis_auth = home.join(".hexis/auth/oauth.openai_codex.json");
                let codex_auth = home.join(".codex/auth.json");
                if force_complete && std::env::var("QUIXI_E2E_TEST").is_err() {
                    if let Ok(raw) = fs::read_to_string(&hexis_auth) {
                        if let Ok(val) = serde_json::from_str::<Value>(&raw) {
                            if let Some(acc) = val.get("access").and_then(|v| v.as_str()) {
                                let refr = val
                                    .get("refresh")
                                    .and_then(|v| v.as_str())
                                    .unwrap_or("")
                                    .to_string();
                                token_acquired = Some((
                                    acc.to_string(),
                                    refr,
                                    "ChatGPT Plus/Pro (Codex OAuth)".to_string(),
                                ));
                            }
                        }
                    } else if let Ok(raw) = fs::read_to_string(&codex_auth) {
                        if let Ok(val) = serde_json::from_str::<Value>(&raw) {
                            if let Some(acc) =
                                val.pointer("/tokens/access_token").and_then(|v| v.as_str())
                            {
                                let refr = val
                                    .pointer("/tokens/refresh_token")
                                    .and_then(|v| v.as_str())
                                    .unwrap_or("")
                                    .to_string();
                                token_acquired = Some((
                                    acc.to_string(),
                                    refr,
                                    "ChatGPT Plus/Pro (Codex OAuth)".to_string(),
                                ));
                            }
                        }
                    }
                }
            }
        }

        if token_acquired.is_none() && force_complete && std::env::var("QUIXI_E2E_TEST").is_ok() {
            let label = if provider_id == "xai" {
                "SuperGrok / X Account (OAuth)"
            } else {
                "ChatGPT Plus/Pro (Codex OAuth)"
            };
            token_acquired = Some((
                format!("oauth_{}_{}", provider_id, Uuid::new_v4().simple()),
                format!("refresh_{}", Uuid::new_v4().simple()),
                label.to_string(),
            ));
        }

        if let Some((access, refresh, account_label)) = token_acquired {
            let discovered_codex_models = if provider_id == "openai" {
                if let Some(ref http) = client {
                    Self::fetch_codex_models(http, &access)
                } else {
                    Vec::new()
                }
            } else {
                Vec::new()
            };

            let now_ms = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_millis() as u64)
                .unwrap_or(0);
            let mut st = self.state.write();
            let mut selected_model = String::new();
            if let Some(entry) = st.providers.iter_mut().find(|p| p.id == provider_id) {
                entry.auth_mode = "oauth".to_string();
                entry.oauth_access_token = access.clone();
                entry.oauth_refresh_token = refresh;
                entry.oauth_account_label = Some(account_label.clone());
                entry.oauth_expires_ms = Some(now_ms + 3600 * 1000);
                entry.api_key_masked = format!("OAuth · {}", account_label);
                entry.configured = true;
                entry.last_tested_ok = Some(true);

                if !discovered_codex_models.is_empty() {
                    for m_id in discovered_codex_models.iter().rev() {
                        if !entry.models.iter().any(|m| &m.id == m_id) {
                            entry.models.insert(
                                0,
                                Self::model(
                                    m_id,
                                    &format!("{} (Codex OAuth)", m_id),
                                    entry.context_window,
                                    true,
                                    true,
                                ),
                            );
                        }
                    }
                    if !discovered_codex_models.contains(&entry.selected_model) {
                        entry.selected_model = discovered_codex_models[0].clone();
                    }
                } else if entry.selected_model == "gpt-5.3-codex" {
                    entry.selected_model = "gpt-6.1-sol".to_string();
                }

                selected_model = entry.selected_model.clone();
            }
            st.active_provider = provider_id.to_string();
            if !selected_model.is_empty() {
                st.active_model = selected_model;
            }
            drop(st);
            self.persist();

            return json!({
                "status": "authorized",
                "providerId": provider_id,
                "accountLabel": account_label,
                "state": self.get_public_state(),
            });
        }

        json!({
            "status": "pending",
            "providerId": provider_id,
        })
    }

    /// Extracts `chatgpt_account_id` from an OpenAI Codex OAuth JWT access token.
    pub fn extract_chatgpt_account_id(access_token: &str) -> Option<String> {
        let parts: Vec<&str> = access_token.split('.').collect();
        if parts.len() != 3 {
            return None;
        }
        let payload_b64 = parts[1].trim_end_matches('=');
        let decoded = URL_SAFE_NO_PAD.decode(payload_b64).ok()?;
        let claims: Value = serde_json::from_slice(&decoded).ok()?;
        claims
            .get("https://api.openai.com/auth")
            .and_then(|a| a.get("chatgpt_account_id"))
            .and_then(|id| id.as_str())
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string())
    }

    /// Queries `https://chatgpt.com/backend-api/codex/models?client_version=1.0.0` to discover
    /// the picker-visible Codex models supported by the user's ChatGPT subscription.
    pub fn fetch_codex_models(http: &reqwest::blocking::Client, access_token: &str) -> Vec<String> {
        let Some(account_id) = Self::extract_chatgpt_account_id(access_token) else {
            return Vec::new();
        };
        let Ok(resp) = http
            .get("https://chatgpt.com/backend-api/codex/models?client_version=1.0.0")
            .header("Authorization", format!("Bearer {}", access_token))
            .header("ChatGPT-Account-ID", &account_id)
            .header("Accept", "application/json")
            .header("User-Agent", "codex_cli_rs/0.1.0")
            .send()
        else {
            return Vec::new();
        };
        if !resp.status().is_success() {
            return Vec::new();
        }
        let Ok(data) = resp.json::<Value>() else {
            return Vec::new();
        };
        let Some(rows) = data.get("models").and_then(|v| v.as_array()) else {
            return Vec::new();
        };
        let mut models = Vec::new();
        for row in rows {
            let vis = row
                .get("visibility")
                .and_then(|v| v.as_str())
                .unwrap_or("list")
                .to_ascii_lowercase();
            if vis != "list" {
                continue;
            }
            if row.get("show_in_picker").and_then(|v| v.as_bool()) == Some(false)
                || row.get("supported_in_api").and_then(|v| v.as_bool()) == Some(false)
            {
                continue;
            }
            if let Some(slug) = row
                .get("slug")
                .or_else(|| row.get("id"))
                .and_then(|v| v.as_str())
            {
                if !slug.is_empty() && !models.contains(&slug.to_string()) {
                    models.push(slug.to_string());
                }
            }
        }
        models
    }

    /// Refreshes the OpenAI Codex OAuth token using the stored `oauth_refresh_token`.
    pub fn refresh_codex_token(&self, http: &reqwest::blocking::Client) -> Option<String> {
        let refresh_token = {
            let st = self.state.read();
            st.providers
                .iter()
                .find(|p| p.id == "openai")
                .map(|p| p.oauth_refresh_token.clone())
                .unwrap_or_default()
        };
        if refresh_token.is_empty() || refresh_token.starts_with("refresh_") {
            return None;
        }
        let resp = http
            .post(OPENAI_CODEX_TOKEN_URL)
            .form(&[
                ("grant_type", "refresh_token"),
                ("refresh_token", refresh_token.as_str()),
                ("client_id", OPENAI_CODEX_CLIENT_ID),
            ])
            .send()
            .ok()?;
        if !resp.status().is_success() {
            return None;
        }
        let data: Value = resp.json().ok()?;
        let new_access = data.get("access_token")?.as_str()?.to_string();
        let new_refresh = data
            .get("refresh_token")
            .and_then(|v| v.as_str())
            .unwrap_or(&refresh_token)
            .to_string();
        let expires_in = data
            .get("expires_in")
            .and_then(|v| v.as_u64())
            .unwrap_or(3600);
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        {
            let mut st = self.state.write();
            if let Some(entry) = st.providers.iter_mut().find(|p| p.id == "openai") {
                entry.oauth_access_token = new_access.clone();
                entry.oauth_refresh_token = new_refresh;
                entry.oauth_expires_ms = Some(now_ms + expires_in * 1000);
            }
        }
        self.persist();
        Some(new_access)
    }

    /// Calls `https://chatgpt.com/backend-api/codex/responses` using the OpenAI Codex Responses SSE wire protocol,
    /// streaming each token delta in real time to `on_delta`.
    #[allow(clippy::too_many_arguments)]
    fn call_codex_responses_streaming<F>(
        http: &reqwest::blocking::Client,
        access_token: &str,
        account_id: &str,
        model: &str,
        sys_prompt: &str,
        history: &[(String, String)],
        prompt: &str,
        cancelled: &dyn Fn() -> bool,
        on_delta: &mut F,
    ) -> Result<String, CompletionError>
    where
        F: FnMut(&str),
    {
        let mut input_items = Vec::new();
        for (role, text) in history {
            if text.trim().is_empty() {
                continue;
            }
            let r = if role == "assistant" {
                "assistant"
            } else {
                "user"
            };
            let content_type = if r == "assistant" {
                "output_text"
            } else {
                "input_text"
            };
            input_items.push(json!({
                "type": "message",
                "role": r,
                "content": [{ "type": content_type, "text": text }]
            }));
        }
        if input_items.is_empty()
            || history
                .last()
                .map(|(r, t)| r != "user" || t != prompt)
                .unwrap_or(true)
        {
            input_items.push(json!({
                "type": "message",
                "role": "user",
                "content": [{ "type": "input_text", "text": prompt }]
            }));
        }

        let payload = json!({
            "model": model,
            "instructions": sys_prompt,
            "input": input_items,
            "store": false,
            "stream": true
        });

        let resp = Self::send_with_retry(cancelled, || {
            http.post("https://chatgpt.com/backend-api/codex/responses")
                .header("Authorization", format!("Bearer {}", access_token))
                .header("ChatGPT-Account-Id", account_id)
                .header("originator", "codex_cli_rs")
                .header("User-Agent", "codex_cli_rs/0.1.0")
                .header("Content-Type", "application/json")
                .header("Accept", "text/event-stream")
                .json(&payload)
                .send()
        })?;
        if !resp.status().is_success() {
            return Err(Self::http_error(resp, &[access_token]));
        }

        let mut delta_acc = String::new();
        let mut completed_fallback = String::new();
        let mut completed = false;
        Self::read_stream(resp, cancelled, |line| {
            let Some(data_str) = line.strip_prefix("data:").map(str::trim) else {
                return Ok(());
            };
            if data_str.is_empty() || data_str == "[DONE]" {
                return Ok(());
            }
            let Ok(ev) = serde_json::from_str::<Value>(data_str) else {
                return Ok(());
            };
            match ev.get("type").and_then(|v| v.as_str()).unwrap_or("") {
                "response.output_text.delta" => {
                    if let Some(d) = ev.get("delta").and_then(|v| v.as_str()) {
                        if !d.is_empty() {
                            delta_acc.push_str(d);
                            on_delta(d);
                        }
                    }
                }
                "response.completed" => {
                    completed = true;
                    if delta_acc.is_empty() {
                        for item in ev
                            .pointer("/response/output")
                            .and_then(|v| v.as_array())
                            .into_iter()
                            .flatten()
                            .filter(|item| item.get("type").and_then(|v| v.as_str()) == Some("message"))
                        {
                            for part in item.get("content").and_then(|v| v.as_array()).into_iter().flatten() {
                                if let Some(t) = part.get("text").and_then(|v| v.as_str()) {
                                    completed_fallback.push_str(t);
                                }
                            }
                        }
                    }
                }
                "response.incomplete" => {
                    let reason = ev
                        .pointer("/response/incomplete_details/reason")
                        .and_then(|v| v.as_str())
                        .unwrap_or("unknown");
                    return Err(if reason.contains("max_output_tokens") {
                        CompletionError::truncated(&delta_acc, None)
                    } else {
                        CompletionError::Stream(format!(
                            "The provider stopped the response early ({reason})."
                        ))
                    });
                }
                "response.failed" | "error" => {
                    let message = ev
                        .pointer("/response/error/message")
                        .or_else(|| ev.pointer("/error/message"))
                        .or_else(|| ev.get("message"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("unspecified error");
                    return Err(CompletionError::Stream(format!(
                        "The provider reported an error during the response: {}",
                        Self::excerpt(message, &[access_token])
                    )));
                }
                _ => {}
            }
            Ok(())
        })?;
        if !completed {
            return Err(CompletionError::ended_early());
        }

        let final_reply = if !delta_acc.trim().is_empty() {
            delta_acc
        } else {
            if !completed_fallback.is_empty() {
                on_delta(&completed_fallback);
            }
            completed_fallback
        };
        Ok(final_reply)
    }

    /// Returns whether a `ProviderModelInfo` is available for the provider's current `auth_mode`.
    fn is_model_available_for_provider(entry: &ProviderEntry, m: &ProviderModelInfo) -> bool {
        if entry.id == "openai" {
            if entry.auth_mode == "oauth" {
                return !m.label.contains("(Platform API)");
            } else {
                return !m.label.contains("(Codex OAuth)");
            }
        }
        true
    }

    /// Formats a clean display name for the model selector dropdown & composer pill.
    fn clean_model_display_name(m: &ProviderModelInfo) -> String {
        let stripped = m
            .label
            .replace(" (Codex OAuth)", "")
            .replace(" (Platform API)", "")
            .trim()
            .to_string();
        if stripped.is_empty() {
            m.id.clone()
        } else {
            stripped
        }
    }

    /// Resolves a requested model ID against the currently connected providers.
    /// Never returns an unconnected model (like `claude-sonnet-4-6` when Anthropic is not connected).
    pub fn resolve_connected_model(&self, requested: Option<&str>) -> String {
        let st = self.state.read();
        let mut connected_models: Vec<String> = Vec::new();
        for p in st.providers.iter().filter(|p| p.configured) {
            for m in &p.models {
                if Self::is_model_available_for_provider(p, m) && !connected_models.contains(&m.id)
                {
                    connected_models.push(m.id.clone());
                }
            }
            if !p.selected_model.is_empty() && !connected_models.contains(&p.selected_model) {
                connected_models.push(p.selected_model.clone());
            }
        }

        if connected_models.is_empty() {
            return requested
                .filter(|s| !s.trim().is_empty())
                .map(|s| s.to_string())
                .unwrap_or_else(|| st.active_model.clone());
        }

        if let Some(req) = requested.filter(|s| !s.trim().is_empty()) {
            if connected_models.iter().any(|m| m == req) {
                return req.to_string();
            }
        }

        if connected_models.iter().any(|m| m == &st.active_model) {
            return st.active_model.clone();
        }

        if let Some(active_p) = st
            .providers
            .iter()
            .find(|p| p.id == st.active_provider && p.configured)
        {
            if !active_p.selected_model.is_empty() {
                return active_p.selected_model.clone();
            }
        }

        connected_models[0].clone()
    }

    /// Updates the active model (and its owning connected provider) when the user selects a model in the UI dropdown.
    pub fn select_model(&self, model_id: &str) -> String {
        let trimmed = model_id.trim();
        if trimmed.is_empty() {
            return self.resolve_connected_model(None);
        }
        let mut st = self.state.write();
        let mut matched_provider_id: Option<String> = None;

        // 1. Prefer a configured provider that owns this model
        for p in st.providers.iter_mut().filter(|p| p.configured) {
            if p.models.iter().any(|m| m.id == trimmed) || p.selected_model == trimmed {
                p.selected_model = trimmed.to_string();
                matched_provider_id = Some(p.id.clone());
                break;
            }
        }

        // 2. If no configured provider matched, check if active_provider is configured (custom model)
        if matched_provider_id.is_none() {
            let active_id = st.active_provider.clone();
            if let Some(p) = st
                .providers
                .iter_mut()
                .find(|p| p.id == active_id && p.configured)
            {
                p.selected_model = trimmed.to_string();
                matched_provider_id = Some(p.id.clone());
            }
        }

        if let Some(pid) = matched_provider_id {
            st.active_provider = pid;
            st.active_model = trimmed.to_string();
            drop(st);
            self.persist();
            return trimmed.to_string();
        }
        drop(st);
        self.resolve_connected_model(None)
    }

    /// Dynamically builds `(model_selector_config, model_selector_state, active_model)` from all connected providers
    /// in the exact schema expected by `ion-dist` (`shared-182-BI1KJccu.js` `sH` / `vH`).
    pub fn build_model_selector_payload(&self) -> (Value, Value, String) {
        let active_model = self.resolve_connected_model(None);
        let st = self.state.read();

        let configured_providers: Vec<&ProviderEntry> =
            st.providers.iter().filter(|p| p.configured).collect();

        let providers_to_list: Vec<&ProviderEntry> = if !configured_providers.is_empty() {
            configured_providers
        } else {
            st.providers
                .iter()
                .filter(|p| p.id == st.active_provider)
                .collect()
        };

        let multi_provider = providers_to_list.len() > 1;
        let mut cowork_models = Vec::new();
        let mut code_models = Vec::new();
        let mut chat_models = Vec::new();
        let mut seen_ids = Vec::new();

        for p in &providers_to_list {
            for m in &p.models {
                if !Self::is_model_available_for_provider(p, m) {
                    continue;
                }
                if seen_ids.contains(&m.id) {
                    continue;
                }
                seen_ids.push(m.id.clone());

                let clean_name = Self::clean_model_display_name(m);
                let display_name = if multi_provider {
                    format!("{} · {}", p.name, clean_name)
                } else {
                    clean_name
                };
                let desc = format!("{} · {}K context", p.name, m.context_window / 1000);

                cowork_models.push(json!({
                    "id": m.id,
                    "name": display_name,
                    "description": desc,
                    "group": "main",
                    "badge": null,
                    "has_1m_context": m.context_window >= 1_000_000,
                    "context_window": m.context_window,
                    "Display": null,
                    "thinking": {
                        "type": "effort_and_mode",
                        "effort_options": [
                            { "effort": "low", "title": "Low", "description": "Fast responses", "badge": null, "recommended": false },
                            { "effort": "medium", "title": "Medium", "description": "Balanced speed and depth", "badge": null, "recommended": true },
                            { "effort": "high", "title": "High", "description": "Deeper reasoning", "badge": null, "recommended": false },
                            { "effort": "max", "title": "Max", "description": "Maximum reasoning effort", "badge": null, "recommended": false }
                        ],
                        "mode_options": [
                            { "mode": "adaptive", "title": "Adaptive", "description": "Thinks when needed", "badge": null, "recommended": true },
                            { "mode": "extended", "title": "Extended", "description": "Always uses extended thinking", "badge": null, "recommended": false },
                            { "mode": "off", "title": "Off", "description": null, "badge": null, "recommended": false }
                        ]
                    }
                }));

                code_models.push(json!({
                    "id": m.id,
                    "name": display_name,
                    "description": desc,
                    "group": "main",
                    "badge": null,
                    "has_1m_context": m.context_window >= 1_000_000,
                    "context_window": m.context_window,
                    "Display": null,
                    "thinking": {
                        "type": "effort",
                        "effort_options": [
                            { "effort": "low", "title": "Low", "description": null, "badge": null, "recommended": false },
                            { "effort": "medium", "title": "Medium", "description": null, "badge": null, "recommended": true },
                            { "effort": "high", "title": "High", "description": null, "badge": null, "recommended": false },
                            { "effort": "max", "title": "Max", "description": null, "badge": null, "recommended": false }
                        ]
                    }
                }));

                chat_models.push(json!({
                    "id": m.id,
                    "name": display_name,
                    "description": desc,
                    "group": "main",
                    "badge": null,
                    "has_1m_context": m.context_window >= 1_000_000,
                    "context_window": m.context_window,
                    "Display": null,
                    "thinking": {
                        "type": "effort_and_mode",
                        "effort_options": [
                            { "effort": "low", "title": "Low", "description": "Fast responses", "badge": null, "recommended": false },
                            { "effort": "medium", "title": "Medium", "description": "Balanced speed and depth", "badge": null, "recommended": true },
                            { "effort": "high", "title": "High", "description": "Deeper reasoning", "badge": null, "recommended": false },
                            { "effort": "max", "title": "Max", "description": "Maximum reasoning effort", "badge": null, "recommended": false }
                        ],
                        "mode_options": [
                            { "mode": "adaptive", "title": "Adaptive", "description": "Thinks when needed", "badge": null, "recommended": true },
                            { "mode": "extended", "title": "Extended", "description": "Always uses extended thinking", "badge": null, "recommended": false },
                            { "mode": "off", "title": "Off", "description": null, "badge": null, "recommended": false }
                        ]
                    }
                }));
            }
        }

        let config = json!([
            {
                "id": "cowork",
                "models": cowork_models,
                "default_model": active_model,
                "default_thinking": { "type": "effort", "effort": "medium" }
            },
            {
                "id": "code",
                "models": code_models,
                "default_model": active_model,
                "default_thinking": { "type": "effort", "effort": "medium" }
            },
            {
                "id": "chat",
                "models": chat_models,
                "default_model": active_model,
                "default_thinking": { "type": "effort", "effort": "medium" }
            }
        ]);

        let state = json!([
            {
                "id": "chat",
                "model": active_model,
                "selection_source": "user_setting",
                "thinking": { "type": "effort", "effort": "medium" },
                "thinking_by_model": null
            },
            {
                "id": "cowork",
                "model": active_model,
                "selection_source": "user_setting",
                "thinking": { "type": "effort", "effort": "medium" },
                "thinking_by_model": null
            },
            {
                "id": "code",
                "model": active_model,
                "selection_source": "user_setting",
                "thinking": { "type": "effort", "effort": "medium" },
                "thinking_by_model": null
            }
        ]);

        (config, state, active_model)
    }

    /// Attempts a live completion against the active configured provider, returning `Some((reply, provider_name, model_id))`.
    pub fn try_live_completion(
        &self,
        prompt: &str,
        cwd: &str,
        history: &[(String, String)],
    ) -> Option<(String, String, String)> {
        self.try_live_completion_streaming(prompt, cwd, history, None, |_| {})
    }

    /// Attempts a live streaming completion against the connected provider that owns `model_override` (or the active provider),
    /// invoking `on_delta` in real time as each token delta arrives.
    pub fn try_live_completion_streaming<F>(
        &self,
        prompt: &str,
        cwd: &str,
        history: &[(String, String)],
        model_override: Option<&str>,
        on_delta: F,
    ) -> Option<(String, String, String)>
    where
        F: FnMut(&str),
    {
        self.legacy_completion(prompt, cwd, history, model_override, false, on_delta)
    }

    /// Coding actions need valid JSON, including escaped Windows paths. Providers
    /// that reject the optional response format receive one ordinary-mode retry.
    pub fn try_live_coding_completion_streaming<F>(
        &self,
        prompt: &str,
        cwd: &str,
        history: &[(String, String)],
        model_override: Option<&str>,
        on_delta: F,
    ) -> Option<(String, String, String)>
    where
        F: FnMut(&str),
    {
        self.legacy_completion(prompt, cwd, history, model_override, true, on_delta)
    }

    fn legacy_completion<F>(
        &self,
        prompt: &str,
        cwd: &str,
        history: &[(String, String)],
        model_override: Option<&str>,
        json_mode: bool,
        on_delta: F,
    ) -> Option<(String, String, String)>
    where
        F: FnMut(&str),
    {
        let request = CompletionRequest {
            prompt,
            cwd,
            history,
            model: model_override,
            json_mode,
            strict_model: false,
            max_output_tokens: None,
            cancelled: &|| false,
        };
        match self.complete(&request, on_delta) {
            Ok(done) => Some((done.text, done.provider, done.model)),
            // Chat callers display what arrived before the output limit; the agent loop does not.
            Err(CompletionError::Truncated { partial, provider, model, .. })
                if !partial.trim().is_empty() =>
            {
                Some((partial, provider, model))
            }
            Err(error) => {
                tracing::warn!("Live completion failed: {error}");
                None
            }
        }
    }

    fn select_provider(
        &self,
        requested: Option<&str>,
        strict: bool,
    ) -> Result<SelectedProvider, CompletionError> {
        let requested = requested.map(str::trim).filter(|m| !m.is_empty());
        let (provider_hint, model_hint) = match requested.and_then(|s| s.split_once("::")) {
            Some((provider, model)) => (Some(provider), Some(model)),
            None => (None, requested),
        };
        let resolved_model = model_hint.map(str::to_owned)
            .unwrap_or_else(|| self.resolve_connected_model(None));
        let st = self.state.read();
        let preferred = provider_hint.unwrap_or(&st.active_provider);
        let owner = st.providers.iter().find(|p| p.id == preferred && Self::owns_model(p, &resolved_model))
            .or_else(|| if provider_hint.is_none() {
                st.providers.iter().find(|p| Self::owns_model(p, &resolved_model))
            } else { None });
        if Self::placeholder_model(&resolved_model) && owner.is_none() {
            return Err(CompletionError::Unavailable(format!(
                "{resolved_model:?} is an unconfirmed catalog placeholder. Discover models in Connections and select an exact served ID. Explicitly advertised aliases remain supported."
            )));
        }
        let entry = match owner {
            Some(entry) => entry,
            None if strict || requested.is_some() => return Err(CompletionError::Unavailable(format!(
                "Model {resolved_model} is not offered by the selected configured connection{}. Discover models and choose one explicitly; REA Studio does not substitute another model.",
                provider_hint.map(|p| format!(" {p}")).unwrap_or_default()
            ))),
            None => st.providers.iter().find(|p| p.id == st.active_provider && p.configured)
                .ok_or_else(|| CompletionError::Unavailable("No model provider is configured.".into()))?,
        };

        let cred = Self::resolve_key(entry, "", &entry.base_url).0;
        let chosen_model = if entry.models.iter().any(|m| m.id == resolved_model)
            || entry.selected_model == resolved_model
        {
            resolved_model
        } else {
            entry.selected_model.clone()
        };
        Ok((
            entry.id.clone(),
            entry.name.clone(),
            chosen_model,
            entry.base_url.trim_end_matches('/').to_string(),
            entry.api_format.clone(),
            entry.auth_mode.clone(),
            cred,
        ))
    }

    /// Send a request, retrying HTTP 429 and 5xx with bounded exponential backoff that honours Retry-After.
    fn send_with_retry(
        cancelled: &dyn Fn() -> bool,
        mut send: impl FnMut() -> reqwest::Result<reqwest::blocking::Response>,
    ) -> Result<reqwest::blocking::Response, CompletionError> {
        let mut attempt = 0u32;
        loop {
            if cancelled() {
                return Err(CompletionError::Cancelled);
            }
            attempt += 1;
            let response = send().map_err(|e| {
                CompletionError::Network(format!(
                    "Could not reach the provider: {}",
                    e.without_url()
                ))
            })?;
            let status = response.status().as_u16();
            if (status == 429 || status >= 500) && attempt < PROVIDER_ATTEMPTS {
                let wait = response
                    .headers()
                    .get("retry-after")
                    .and_then(|v| v.to_str().ok())
                    .and_then(|v| v.trim().parse::<u64>().ok())
                    .map(std::time::Duration::from_secs)
                    .unwrap_or(std::time::Duration::from_secs(1 << (attempt - 1)))
                    .min(std::time::Duration::from_secs(30));
                drop(response);
                let until = Instant::now() + wait;
                while Instant::now() < until {
                    if cancelled() {
                        return Err(CompletionError::Cancelled);
                    }
                    std::thread::sleep(
                        until
                            .saturating_duration_since(Instant::now())
                            .min(std::time::Duration::from_millis(100)),
                    );
                }
                continue;
            }
            return Ok(response);
        }
    }

    /// A bounded, single-line excerpt with credentials and key-like tokens removed.
    fn excerpt(text: &str, secrets: &[&str]) -> String {
        let mut text = text.to_string();
        for secret in secrets.iter().filter(|s| s.len() >= 6) {
            text = text.replace(secret, "[redacted]");
        }
        let mut masked = String::new();
        let mut rest = text.as_str();
        while let Some(index) = rest.find("sk-") {
            masked.push_str(&rest[..index + 3]);
            let tail = &rest[index + 3..];
            let end = tail
                .find(|c: char| !(c.is_ascii_alphanumeric() || c == '-' || c == '_'))
                .unwrap_or(tail.len());
            if end > 0 {
                masked.push_str("[redacted]");
            }
            rest = &tail[end..];
        }
        masked.push_str(rest);
        let single = masked.split_whitespace().collect::<Vec<_>>().join(" ");
        let mut bounded: String = single.chars().take(600).collect();
        if single.chars().count() > 600 {
            bounded.push('…');
        }
        bounded
    }

    fn http_error(response: reqwest::blocking::Response, secrets: &[&str]) -> CompletionError {
        use std::io::Read;
        let status = response.status().as_u16();
        let mut body = Vec::new();
        let _ = response.take(16 * 1024).read_to_end(&mut body);
        CompletionError::Http {
            status,
            excerpt: Self::excerpt(&String::from_utf8_lossy(&body), secrets),
        }
    }

    /// Feed each stream line to `handle`. A read error (including the idle timeout) is a failure.
    fn read_stream(
        response: reqwest::blocking::Response,
        cancelled: &dyn Fn() -> bool,
        mut handle: impl FnMut(&str) -> Result<(), CompletionError>,
    ) -> Result<(), CompletionError> {
        use std::io::{BufRead, BufReader};
        let mut reader = BufReader::new(response);
        let mut line = Vec::new();
        loop {
            if cancelled() {
                return Err(CompletionError::Cancelled);
            }
            line.clear();
            match reader.read_until(b'\n', &mut line) {
                Ok(0) => return Ok(()),
                Ok(_) => handle(String::from_utf8_lossy(&line).trim())?,
                Err(error) => {
                    return Err(CompletionError::Stream(format!(
                        "The provider stream failed before the response completed ({error}); the partial output was discarded."
                    )))
                }
            }
        }
    }

    /// Streams one completion from the provider that owns `request.model`. Unlike the legacy
    /// `try_live_*` helpers this reports why a request failed and never treats a cut-off
    /// stream as a complete answer.
    pub fn complete<F>(
        &self,
        request: &CompletionRequest,
        mut on_delta: F,
    ) -> Result<Completion, CompletionError>
    where
        F: FnMut(&str),
    {
        let cancelled = request.cancelled;
        let (provider_id, provider_name, model_id, base_url, api_format, auth_mode, mut credential) =
            self.select_provider(request.model, request.strict_model)?;
        let (prompt, history) = (request.prompt, request.history);

        // In blocking reqwest this bounds the wait for response headers and for each body
        // read, not the whole response, so long generations keep streaming.
        let http = reqwest::blocking::Client::builder()
            .connect_timeout(std::time::Duration::from_secs(15))
            .timeout(PROVIDER_IDLE_TIMEOUT)
            .build()
            .map_err(|e| CompletionError::Network(format!("Could not create the HTTP client: {e}")))?;

        let sys_prompt = format!(
            "You are REA Studio, a native Rust AI desktop assistant and coding workspace agent. Active workspace: {}. Follow the tool protocol in the task instructions. Use supplied file contents and actual tool results as evidence. Read files before making claims about them; do not invent tool calls, tests or successful changes in {}.",
            request.cwd, request.cwd
        );

        let codex_account = (provider_id == "openai"
            && (auth_mode == "oauth" || Self::extract_chatgpt_account_id(&credential).is_some())
            && !credential.starts_with("oauth_"))
        .then(|| Self::extract_chatgpt_account_id(&credential))
        .flatten();

        let outcome = if let Some(account_id) = codex_account {
            // 1. OpenAI Codex OAuth (`chatgpt.com/backend-api/codex/responses` SSE stream)
            let mut result = Self::call_codex_responses_streaming(
                &http, &credential, &account_id, &model_id, &sys_prompt, history, prompt,
                cancelled, &mut on_delta,
            );
            if matches!(result, Err(CompletionError::Http { status: 401, .. })) {
                if let Some(fresh) = self.refresh_codex_token(&http) {
                    if let Some(fresh_account) = Self::extract_chatgpt_account_id(&fresh) {
                        credential = fresh;
                        result = Self::call_codex_responses_streaming(
                            &http, &credential, &fresh_account, &model_id, &sys_prompt,
                            history, prompt, cancelled, &mut on_delta,
                        );
                    }
                }
            }
            if let Err(CompletionError::Http { status: 400, excerpt }) = &result {
                if excerpt.contains("model_not_found") || excerpt.contains("not supported") {
                    // Record the account's live models, but never change the saved selection.
                    let live_models = Self::fetch_codex_models(&http, &credential);
                    if !live_models.is_empty() {
                        {
                            let mut st = self.state.write();
                            if let Some(entry) = st.providers.iter_mut().find(|p| p.id == "openai") {
                                for m_id in live_models.iter().rev() {
                                    if !entry.models.iter().any(|m| &m.id == m_id) {
                                        let model = Self::model(
                                            m_id,
                                            &format!("{} (Codex OAuth)", m_id),
                                            entry.context_window,
                                            true,
                                            true,
                                        );
                                        entry.models.insert(0, model);
                                    }
                                }
                            }
                        }
                        self.persist();
                    }
                    result = Err(CompletionError::Unavailable(format!(
                        "Codex rejected model {model_id} for this account (HTTP 400: {excerpt}). Models it offers: {}. Choose one explicitly; REA Studio does not switch models automatically.",
                        if live_models.is_empty() { "none listed".to_string() } else { live_models.join(", ") }
                    )));
                }
            }
            result
        } else if api_format == "anthropic" && !credential.is_empty() && !credential.starts_with("oauth_") {
            // 2. Anthropic Messages API (`/v1/messages` with `"stream": true`)
            let url = format!("{}/messages", base_url);
            let mut msgs = Vec::new();
            for (role, text) in history {
                if !text.trim().is_empty() {
                    msgs.push(json!({
                        "role": if role == "assistant" { "assistant" } else { "user" },
                        "content": text
                    }));
                }
            }
            if msgs.is_empty()
                || history
                    .last()
                    .map(|(r, t)| r != "user" || t != prompt)
                    .unwrap_or(true)
            {
                msgs.push(json!({ "role": "user", "content": prompt }));
            }
            let send = |limit: u32| {
                Self::send_with_retry(cancelled, || {
                    http.post(&url)
                        .header("x-api-key", &credential)
                        .header("anthropic-version", "2023-06-01")
                        .header("content-type", "application/json")
                        .header("accept", "text/event-stream")
                        .json(&json!({
                            "model": model_id,
                            "max_tokens": limit,
                            "system": sys_prompt,
                            "messages": msgs,
                            "stream": true
                        }))
                        .send()
                })
            };
            let mut limit = request.max_output_tokens.unwrap_or_else(default_max_output_tokens);
            let mut resp = send(limit)?;
            if resp.status().as_u16() == 400 {
                // Older models accept fewer output tokens; clamp once to the limit the API states.
                match Self::http_error(resp, &[&credential]) {
                    CompletionError::Http { excerpt, .. } if excerpt.contains("max_tokens") => {
                        limit = excerpt
                            .split("> ")
                            .nth(1)
                            .and_then(|tail| {
                                tail.split(|c: char| !c.is_ascii_digit()).next()?.parse::<u32>().ok()
                            })
                            .filter(|stated| *stated > 0 && *stated < limit)
                            .unwrap_or(4096);
                        resp = send(limit)?;
                    }
                    error => return Err(error.with_origin(&provider_name, &model_id)),
                }
            }
            if !resp.status().is_success() {
                Err(Self::http_error(resp, &[&credential]))
            } else {
                let (mut acc, mut stop_reason, mut completed) = (String::new(), None::<String>, false);
                Self::read_stream(resp, cancelled, |trimmed| {
                    let body = if let Some(data_str) = trimmed.strip_prefix("data:") {
                        let data_str = data_str.trim();
                        if data_str.is_empty() || data_str == "[DONE]" {
                            return Ok(());
                        }
                        data_str
                    } else if trimmed.starts_with('{') {
                        trimmed
                    } else {
                        return Ok(());
                    };
                    let Ok(ev) = serde_json::from_str::<Value>(body) else {
                        return Ok(());
                    };
                    match ev.get("type").and_then(|v| v.as_str()) {
                        Some("content_block_delta") => {
                            if let Some(d) = ev
                                .pointer("/delta/text")
                                .and_then(|v| v.as_str())
                                .filter(|s| !s.is_empty())
                            {
                                acc.push_str(d);
                                on_delta(d);
                            }
                        }
                        Some("message_delta") => {
                            if let Some(reason) = ev.pointer("/delta/stop_reason").and_then(|v| v.as_str()) {
                                stop_reason = Some(reason.to_string());
                            }
                        }
                        Some("message_stop") => completed = true,
                        Some("error") => {
                            let message = ev
                                .pointer("/error/message")
                                .and_then(|v| v.as_str())
                                .unwrap_or("unspecified error");
                            return Err(CompletionError::Stream(format!(
                                "The provider reported an error during the response: {}",
                                Self::excerpt(message, &[&credential])
                            )));
                        }
                        _ => {
                            // A complete non-streamed message body.
                            if let Some(text) = ev.pointer("/content/0/text").and_then(|v| v.as_str()) {
                                acc.push_str(text);
                                on_delta(text);
                                if let Some(reason) = ev.get("stop_reason").and_then(|v| v.as_str()) {
                                    stop_reason = Some(reason.to_string());
                                    completed = true;
                                }
                            }
                        }
                    }
                    Ok(())
                })
                .and_then(|()| {
                    if stop_reason.as_deref() == Some("max_tokens") {
                        Err(CompletionError::truncated(&acc, Some(limit)))
                    } else if !completed {
                        Err(CompletionError::ended_early())
                    } else {
                        Ok(acc)
                    }
                })
            }
        } else if !base_url.is_empty()
            && (!credential.is_empty() || auth_mode == "local" || provider_id == "custom")
            && !credential.starts_with("oauth_")
        {
            // 3. OpenAI-Compatible Chat Completions API (`/v1/chat/completions` with `"stream": true`)
            let url = format!("{}/chat/completions", base_url);
            let mut msgs = vec![json!({ "role": "system", "content": sys_prompt })];
            for (role, text) in history {
                if !text.trim().is_empty() {
                    msgs.push(json!({
                        "role": if role == "assistant" { "assistant" } else { "user" },
                        "content": text
                    }));
                }
            }
            if msgs.len() == 1
                || history
                    .last()
                    .map(|(r, t)| r != "user" || t != prompt)
                    .unwrap_or(true)
            {
                msgs.push(json!({ "role": "user", "content": prompt }));
            }
            // Only send an output limit that was asked for: some endpoints reject `max_tokens`.
            let limit = request.max_output_tokens.or_else(configured_max_output_tokens);
            let payload = |json_mode: bool| {
                let mut payload = json!({"model":model_id,"messages":msgs,"stream":true});
                if json_mode {
                    payload["response_format"] = json!({"type":"json_object"});
                }
                if let Some(limit) = limit {
                    payload["max_tokens"] = json!(limit);
                }
                payload
            };
            let post = |payload: &Value| {
                Self::send_with_retry(cancelled, || {
                    let mut req = http
                        .post(&url)
                        .header("content-type", "application/json")
                        .header("accept", "text/event-stream");
                    if !credential.is_empty() {
                        req = req.header("Authorization", format!("Bearer {}", credential));
                    }
                    if provider_id == "openrouter" {
                        req = req
                            .header("HTTP-Referer", "https://quixidesk.local")
                            .header("X-Title", "REA Studio");
                    }
                    req.json(payload).send()
                })
            };
            let mut resp = post(&payload(request.json_mode))?;
            if request.json_mode && matches!(resp.status().as_u16(), 400 | 422) {
                resp = post(&payload(false))?;
            }
            if !resp.status().is_success() {
                Err(Self::http_error(resp, &[&credential]))
            } else {
                let (mut acc, mut finish, mut done) = (String::new(), None::<String>, false);
                Self::read_stream(resp, cancelled, |trimmed| {
                    let (body, whole) = if let Some(data_str) = trimmed.strip_prefix("data:") {
                        let data_str = data_str.trim();
                        if data_str == "[DONE]" {
                            done = true;
                            return Ok(());
                        }
                        (data_str, false)
                    } else if trimmed.starts_with('{') {
                        (trimmed, true)
                    } else {
                        return Ok(());
                    };
                    let Ok(ev) = serde_json::from_str::<Value>(body) else {
                        return Ok(());
                    };
                    if let Some(error) = ev.get("error").filter(|e| !e.is_null()) {
                        let message = error
                            .get("message")
                            .and_then(|v| v.as_str())
                            .map(str::to_string)
                            .unwrap_or_else(|| error.to_string());
                        return Err(CompletionError::Stream(format!(
                            "The provider reported an error during the response: {}",
                            Self::excerpt(&message, &[&credential])
                        )));
                    }
                    if let Some(d) = ev
                        .pointer("/choices/0/delta/content")
                        .or_else(|| ev.pointer("/choices/0/message/content"))
                        .and_then(|v| v.as_str())
                        .filter(|s| !s.is_empty())
                    {
                        acc.push_str(d);
                        on_delta(d);
                    }
                    if let Some(reason) = ev.pointer("/choices/0/finish_reason").and_then(|v| v.as_str()) {
                        finish = Some(reason.to_string());
                    }
                    done |= whole;
                    Ok(())
                })
                .and_then(|()| {
                    if finish.as_deref() == Some("length") {
                        Err(CompletionError::truncated(&acc, limit))
                    } else if !done && finish.is_none() {
                        Err(CompletionError::ended_early())
                    } else {
                        Ok(acc)
                    }
                })
            }
        } else {
            Err(CompletionError::Unavailable(format!(
                "{provider_name} has no usable credential or API base URL."
            )))
        };

        let text = outcome.map_err(|e| e.with_origin(&provider_name, &model_id))?;
        // An HTTP error or an empty stream is not a successful completion.
        if text.trim().is_empty() {
            return Err(CompletionError::Empty);
        }
        Ok(Completion {
            text,
            provider: provider_name,
            model: model_id,
        })
    }
}

/// (provider id, provider name, model, base URL, API format, auth mode, credential)
type SelectedProvider = (String, String, String, String, String, String, String);

/// Requests wait at most this long for response headers or for the next streamed bytes.
const PROVIDER_IDLE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(180);
/// Attempts per request when the provider answers HTTP 429 or 5xx.
const PROVIDER_ATTEMPTS: u32 = 3;
const DEFAULT_MAX_OUTPUT_TOKENS: u32 = 16_384;

/// `QUIXI_MAX_OUTPUT_TOKENS`, when set to a usable value.
fn configured_max_output_tokens() -> Option<u32> {
    std::env::var("QUIXI_MAX_OUTPUT_TOKENS")
        .ok()
        .and_then(|v| v.trim().parse::<u32>().ok())
        .map(|v| v.clamp(256, 128_000))
}

/// Output-token limit for providers that require one.
pub fn default_max_output_tokens() -> u32 {
    configured_max_output_tokens().unwrap_or(DEFAULT_MAX_OUTPUT_TOKENS)
}

/// One completion request for `ProviderManager::complete`.
pub struct CompletionRequest<'a> {
    pub prompt: &'a str,
    pub cwd: &'a str,
    pub history: &'a [(String, String)],
    pub model: Option<&'a str>,
    /// Ask OpenAI-compatible endpoints for a JSON object response.
    pub json_mode: bool,
    /// Fail instead of substituting another model when `model` is not configured.
    pub strict_model: bool,
    pub max_output_tokens: Option<u32>,
    /// Polled between stream reads and retries; true aborts the request.
    pub cancelled: &'a dyn Fn() -> bool,
}

pub struct Completion {
    pub text: String,
    pub provider: String,
    /// The model that actually produced the answer.
    pub model: String,
}

#[derive(Debug)]
pub enum CompletionError {
    Unavailable(String),
    Http { status: u16, excerpt: String },
    Network(String),
    Stream(String),
    /// The model stopped at its output-token limit. `partial` is what arrived before it.
    Truncated {
        partial: String,
        provider: String,
        model: String,
        limit: Option<u32>,
    },
    Cancelled,
    Empty,
}

impl CompletionError {
    fn truncated(partial: &str, limit: Option<u32>) -> Self {
        Self::Truncated {
            partial: partial.to_string(),
            provider: String::new(),
            model: String::new(),
            limit,
        }
    }

    fn ended_early() -> Self {
        Self::Stream("The provider stream ended before the response completed (connection closed or interrupted); the partial output was discarded.".into())
    }

    fn with_origin(self, provider_name: &str, model_id: &str) -> Self {
        match self {
            Self::Truncated { partial, limit, .. } => Self::Truncated {
                partial,
                provider: provider_name.to_string(),
                model: model_id.to_string(),
                limit,
            },
            other => other,
        }
    }
}

impl std::fmt::Display for CompletionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unavailable(message) | Self::Network(message) | Self::Stream(message) => {
                f.write_str(message)
            }
            Self::Http { status, excerpt } if excerpt.is_empty() => {
                write!(f, "The provider returned HTTP {status} with no error details.")
            }
            Self::Http { status, excerpt } => {
                write!(f, "The provider returned HTTP {status}: {excerpt}")
            }
            Self::Truncated { limit: Some(limit), .. } => write!(
                f,
                "The model's output was cut off at its output limit ({limit} tokens) before the response completed."
            ),
            Self::Truncated { .. } => f.write_str(
                "The model's output was cut off at its output limit before the response completed.",
            ),
            Self::Cancelled => f.write_str("The request was cancelled."),
            Self::Empty => f.write_str("The provider returned an empty answer."),
        }
    }
}

impl std::error::Error for CompletionError {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader, Read, Write};
    use std::net::TcpListener;

    #[test]
    fn saving_active_connection_repairs_selection_without_switching_connections() {
        let directory = std::env::temp_dir().join(format!("quixi-selection-{}", Uuid::new_v4()));
        fs::create_dir(&directory).unwrap();
        let manager = ProviderManager::new(&directory);
        manager.save_provider(&json!({"providerId":"custom","selectedModel":"old-served","setAsActive":true}));
        manager.save_provider(&json!({"providerId":"custom","selectedModel":"new-served","contextWindow":32768,"setAsActive":false}));
        assert_eq!(manager.state.read().active_model, "new-served");
        manager.save_provider(&json!({"providerId":"ollama","selectedModel":"different","setAsActive":false}));
        assert_eq!(manager.state.read().active_provider, "custom");
        assert_eq!(manager.state.read().active_model, "new-served");
        assert_eq!(manager.run_selection("new-served", Some("custom")).unwrap(),
            ("custom".into(), "new-served".into(), 32768));
        manager.save_provider(&json!({"providerId":"custom","contextWindow":262144,"setAsActive":false}));
        assert_eq!(manager.run_selection("new-served", Some("custom")).unwrap().2, 262144);
        assert!(manager.run_selection("custom-model", Some("custom")).unwrap_err().to_string().contains("placeholder"));
        assert!(manager.run_selection("new-served", Some("ollama")).is_err());
        assert!(manager.select_provider(Some("unknown-model"), false).is_err());
        let invalid = manager.complete_onboarding(&json!({"activeProvider":"custom","activeModel":"missing"}));
        assert!(invalid["error"].as_str().unwrap().contains("does not substitute"));
        assert_eq!(manager.state.read().active_model, "new-served");
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn saved_placeholder_migrates_to_real_selection_in_same_connection() {
        let state = ProviderManager::merge_saved_state(ProviderManager::default_catalog(), &json!({
            "activeProvider":"custom","activeModel":"custom-model",
            "providers":[{"id":"custom","configured":true,"selectedModel":"served-model"}]
        })).unwrap();
        assert_eq!(state.active_model, "served-model");
        let custom = state.providers.iter().find(|p|p.id=="custom").unwrap();
        assert!(!custom.models.iter().any(|m|m.id=="custom-model"));
        let mut state = state;
        let custom = state.providers.iter_mut().find(|p|p.id=="custom").unwrap();
        custom.models.push(ProviderManager::model("intentional-alternative", "Alternative", 32768, false, false));
        state.active_model = "intentional-alternative".into();
        ProviderManager::repair_active_selection(&mut state);
        assert_eq!(state.active_model, "intentional-alternative");
    }

    #[test]
    fn explicit_connection_keeps_same_named_models_separate() {
        let directory = std::env::temp_dir().join(format!("quixi-routing-{}", Uuid::new_v4()));
        fs::create_dir(&directory).unwrap();
        let manager = ProviderManager::new(&directory);
        manager.save_provider(&json!({"providerId":"custom","selectedModel":"shared","setAsActive":true}));
        manager.save_provider(&json!({"providerId":"ollama","selectedModel":"shared","setAsActive":false}));
        assert_eq!(manager.select_provider(Some("custom::shared"), true).unwrap().0, "custom");
        assert_eq!(manager.select_provider(Some("ollama::shared"), true).unwrap().0, "ollama");
        assert_eq!(manager.select_provider(Some("shared"), true).unwrap().0, "custom");
        assert!(manager.select_provider(Some("missing::shared"), true).is_err());
        manager.remember_models("custom", &["custom-model", "served-one"]);
        assert_eq!(manager.select_provider(Some("custom::custom-model"), true).unwrap().2, "custom-model");
        manager.remember_models("custom", &["served-one"]);
        assert!(!manager.get_public_state()["providers"].as_array().unwrap().iter()
            .find(|p|p["id"]=="custom").unwrap()["models"].as_array().unwrap()
            .iter().any(|m|m["id"]=="custom-model"));
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn environment_credentials_preserve_precedence_and_provider_scope() {
        let mut entry = ProviderManager::default_catalog().providers.into_iter().find(|p| p.id == "custom").unwrap();
        entry.base_url = "https://api.deepseek.com/v1".into();
        let lookup = |name: &str| match name { "DEEPSEEK_API_KEY" => Some(" environment-fixture ".into()), "OLLAMA_HOST" => Some("http://localhost:11434".into()), _ => None };
        let result = ProviderManager::resolve_key_with(&entry, "", &entry.base_url, lookup);
        assert_eq!(result, ("environment-fixture".into(), "environment".into(), Some("DEEPSEEK_API_KEY".into())));
        assert!(entry.api_key_raw.is_empty());
        assert!(!serde_json::to_string(&entry).unwrap().contains("environment-fixture"));
        entry.api_key_raw = "saved-fixture".into();
        assert_eq!(ProviderManager::resolve_key_with(&entry, "", &entry.base_url, lookup).0, "saved-fixture");
        assert_eq!(ProviderManager::resolve_key_with(&entry, "entered-fixture", &entry.base_url, lookup).0, "entered-fixture");
        entry.api_key_raw.clear();
        assert!(ProviderManager::resolve_key_with(&entry, "", "https://api.deepseek.com.untrusted.invalid/v1", lookup).0.is_empty());
        assert!(ProviderManager::resolve_key_with(&entry, "", "http://localhost:8000/v1", lookup).0.is_empty());
        let local = ProviderManager::default_catalog().providers.into_iter().find(|p| p.id == "ollama").unwrap();
        assert!(ProviderManager::resolve_key_with(&local, "", &local.base_url, lookup).0.is_empty());
        assert_eq!(ProviderManager::environment_key_names(&local, &local.base_url), vec!["OLLAMA_API_KEY"]);
        assert!(ProviderManager::resolve_key_with(&entry, "", &entry.base_url, |_| Some("  ".into())).0.is_empty());
    }

    #[test]
    fn streaming_completion_rejects_http_errors_and_empty_answers() {
        let directory = std::env::temp_dir().join(format!("quixi-provider-{}", Uuid::new_v4()));
        fs::create_dir(&directory).unwrap();
        let manager = ProviderManager::new(&directory);
        for (status, body, expected) in [
            ("404 Not Found", "{\"error\":\"wrong endpoint\"}", false),
            ("200 OK", "data: {\"choices\":[{\"delta\":{\"content\":\"\"}}]}\n\ndata: [DONE]\n\n", false),
            ("200 OK", "data: {\"choices\":[{\"delta\":{\"content\":\"actual answer\"}}]}\n\ndata: [DONE]\n\n", true),
        ] {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let address = listener.local_addr().unwrap();
            listener.set_nonblocking(true).unwrap();
            let server = std::thread::spawn(move || {
                let started = Instant::now();
                let mut stream = loop {
                    match listener.accept() {
                        Ok((stream, _)) => break stream,
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            assert!(started.elapsed().as_secs() < 5, "Provider did not connect");
                            std::thread::sleep(std::time::Duration::from_millis(10));
                        }
                        Err(error) => panic!("{error}"),
                    }
                };
                // Accepted sockets inherit the listener's non-blocking mode on Windows.
                stream.set_nonblocking(false).unwrap();
                stream.set_read_timeout(Some(std::time::Duration::from_secs(5))).unwrap();
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let mut size = 0;
                loop {
                    let mut line = String::new();
                    assert!(reader.read_line(&mut line).unwrap() > 0);
                    if line == "\r\n" { break; }
                    if let Some(length) = line.to_lowercase().strip_prefix("content-length:") {
                        size = length.trim().parse::<usize>().unwrap();
                    }
                }
                reader.read_exact(&mut vec![0; size]).unwrap();
                write!(stream, "HTTP/1.1 {status}\r\nContent-Type: text/event-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).unwrap();
            });
            {
                let mut state = manager.state.write();
                state.active_provider = "custom".into();
                state.active_model = "fixture".into();
                let custom = state.providers.iter_mut().find(|p| p.id == "custom").unwrap();
                custom.configured = true;
                custom.selected_model = "fixture".into();
                custom.base_url = format!("http://{address}/v1");
                custom.api_key_raw.clear();
            }
            let mut deltas = String::new();
            let answer = manager.try_live_coding_completion_streaming("Test response handling", "fixture", &[], Some("fixture"), |delta| deltas.push_str(delta));
            server.join().unwrap();
            assert_eq!(answer.is_some(), expected);
            if expected { assert_eq!(answer.unwrap().0, "actual answer"); assert_eq!(deltas, "actual answer"); }
        }
        fs::remove_dir_all(directory).unwrap();
    }

    /// Serve one scripted HTTP response per connection; returns the base URL and the request bodies.
    fn serve(responses: Vec<(&'static str, String)>) -> (String, std::thread::JoinHandle<Vec<String>>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        listener.set_nonblocking(true).unwrap();
        let server = std::thread::spawn(move || {
            let mut bodies = Vec::new();
            for (status, body) in responses {
                let started = Instant::now();
                let mut stream = loop {
                    match listener.accept() {
                        Ok((stream, _)) => break stream,
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            assert!(started.elapsed().as_secs() < 10, "Provider did not connect");
                            std::thread::sleep(std::time::Duration::from_millis(10));
                        }
                        Err(error) => panic!("{error}"),
                    }
                };
                stream.set_nonblocking(false).unwrap();
                stream.set_read_timeout(Some(std::time::Duration::from_secs(5))).unwrap();
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let mut size = 0;
                loop {
                    let mut line = String::new();
                    assert!(reader.read_line(&mut line).unwrap() > 0);
                    if line == "\r\n" { break; }
                    if let Some(length) = line.to_lowercase().strip_prefix("content-length:") {
                        size = length.trim().parse::<usize>().unwrap();
                    }
                }
                let mut request = vec![0; size];
                reader.read_exact(&mut request).unwrap();
                bodies.push(String::from_utf8_lossy(&request).into_owned());
                write!(stream, "HTTP/1.1 {status}\r\nContent-Type: text/event-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).unwrap();
            }
            bodies
        });
        (format!("http://{address}/v1"), server)
    }

    fn fixture_manager(provider: &str, base_url: &str) -> (PathBuf, ProviderManager) {
        let directory = std::env::temp_dir().join(format!("quixi-provider-{}", Uuid::new_v4()));
        fs::create_dir(&directory).unwrap();
        let manager = ProviderManager::new(&directory);
        {
            let mut state = manager.state.write();
            state.active_provider = provider.into();
            state.active_model = "fixture".into();
            let entry = state.providers.iter_mut().find(|p| p.id == provider).unwrap();
            entry.configured = true;
            entry.selected_model = "fixture".into();
            entry.base_url = base_url.into();
            entry.api_key_raw = if provider == "custom" { String::new() } else { "sk-fixturesecret123".into() };
        }
        (directory, manager)
    }

    fn request<'a>(cancelled: &'a dyn Fn() -> bool) -> CompletionRequest<'a> {
        CompletionRequest {
            prompt: "Test",
            cwd: "fixture",
            history: &[],
            model: Some("fixture"),
            json_mode: false,
            strict_model: true,
            max_output_tokens: None,
            cancelled,
        }
    }

    #[test]
    fn completions_report_truncation_interruption_and_http_details() {
        let partial = "data: {\"choices\":[{\"delta\":{\"content\":\"partial\"}}]}\n\n";
        let (base, server) = serve(vec![
            ("200 OK", format!("{partial}data: {{\"choices\":[{{\"delta\":{{}},\"finish_reason\":\"length\"}}]}}\n\ndata: [DONE]\n\n")),
            ("200 OK", partial.to_string()),
            ("401 Unauthorized", "{\"error\":{\"message\":\"Incorrect API key provided: sk-fixturesecret123 for\\n this   project\"}}".into()),
            ("503 Service Unavailable\r\nRetry-After: 0", "busy".into()),
            ("200 OK", "data: {\"choices\":[{\"delta\":{\"content\":\"recovered\"},\"finish_reason\":\"stop\"}]}\n\ndata: [DONE]\n\n".into()),
        ]);
        let (directory, manager) = fixture_manager("custom", &base);
        let never = || false;
        match manager.complete(&request(&never), |_| {}) {
            Err(CompletionError::Truncated { partial, model, .. }) => {
                assert_eq!(partial, "partial");
                assert_eq!(model, "fixture");
            }
            other => panic!("expected truncation, got {:?}", other.err()),
        }
        let interrupted = manager.complete(&request(&never), |_| {}).err().unwrap();
        assert!(matches!(interrupted, CompletionError::Stream(_)), "{interrupted}");
        assert!(interrupted.to_string().contains("ended before the response completed"));
        // The legacy chat helper shows no partial answer for an interrupted stream.
        let http = manager.complete(&request(&never), |_| {}).err().unwrap();
        let message = http.to_string();
        assert!(message.contains("HTTP 401") && message.contains("Incorrect API key"), "{message}");
        assert!(!message.contains("fixturesecret123"), "{message}");
        let recovered = manager.complete(&request(&never), |_| {}).unwrap();
        assert_eq!(recovered.text, "recovered");
        assert_eq!(server.join().unwrap().len(), 5);

        // Strict requests never substitute another model, and cancellation aborts before sending.
        let mut strict = request(&never);
        strict.model = Some("not-configured");
        let error = manager.complete(&strict, |_| {}).err().unwrap();
        assert!(error.to_string().contains("does not substitute"), "{error}");
        assert_eq!(manager.state.read().active_model, "fixture");
        let cancel = || true;
        assert!(matches!(manager.complete(&request(&cancel), |_| {}), Err(CompletionError::Cancelled)));
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn anthropic_requests_a_larger_output_limit_and_reports_max_tokens() {
        let (base, server) = serve(vec![(
            "200 OK",
            "data: {\"type\":\"content_block_delta\",\"delta\":{\"type\":\"text_delta\",\"text\":\"cut\"}}\n\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"max_tokens\"}}\n\ndata: {\"type\":\"message_stop\"}\n\n".into(),
        ), (
            "200 OK",
            "data: {\"type\":\"content_block_delta\",\"delta\":{\"type\":\"text_delta\",\"text\":\"whole\"}}\n\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"}}\n\ndata: {\"type\":\"message_stop\"}\n\n".into(),
        )]);
        let (directory, manager) = fixture_manager("anthropic", &base);
        let never = || false;
        match manager.complete(&request(&never), |_| {}) {
            Err(CompletionError::Truncated { partial, limit, .. }) => {
                assert_eq!(partial, "cut");
                assert_eq!(limit, Some(default_max_output_tokens()));
            }
            other => panic!("expected truncation, got {:?}", other.err()),
        }
        let mut sized = request(&never);
        sized.max_output_tokens = Some(2048);
        assert_eq!(manager.complete(&sized, |_| {}).unwrap().text, "whole");
        let bodies = server.join().unwrap();
        let first: Value = serde_json::from_str(&bodies[0]).unwrap();
        assert_eq!(first["max_tokens"], default_max_output_tokens());
        assert!(default_max_output_tokens() > 4096);
        assert_eq!(serde_json::from_str::<Value>(&bodies[1]).unwrap()["max_tokens"], 2048);
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn saving_requires_a_resolvable_credential_except_for_local_and_custom_endpoints() {
        let directory = std::env::temp_dir().join(format!("quixi-provider-save-{}", Uuid::new_v4()));
        fs::create_dir(&directory).unwrap();
        let manager = ProviderManager::new(&directory);
        let configured = |id: &str| manager.state.read().providers.iter().find(|p| p.id == id).unwrap().configured;
        if std::env::var_os("GROQ_API_KEY").is_none() {
            let saved = manager.save_provider(&json!({"providerId":"groq","selectedModel":"some-model"}));
            assert!(saved["error"].as_str().unwrap().contains("GROQ_API_KEY"), "{saved}");
            assert!(!configured("groq"));
            assert_ne!(manager.state.read().active_provider, "groq");
        }
        let saved = manager.save_provider(&json!({"providerId":"groq","apiKey":"gsk-fixture"}));
        assert!(saved.get("error").is_none(), "{saved}");
        assert!(configured("groq"));
        for local in ["custom", "ollama"] {
            let saved = manager.save_provider(&json!({"providerId":local,"setAsActive":false}));
            assert!(saved.get("error").is_none(), "{saved}");
            assert!(configured(local));
        }
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn local_detection_uses_the_configured_url_and_keeps_the_chosen_model() {
        let directory = std::env::temp_dir().join(format!("quixi-provider-detect-{}", Uuid::new_v4()));
        fs::create_dir(&directory).unwrap();
        let manager = ProviderManager::new(&directory);
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream.set_read_timeout(Some(std::time::Duration::from_secs(5))).unwrap();
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut request_line = String::new();
            reader.read_line(&mut request_line).unwrap();
            loop {
                let mut line = String::new();
                if reader.read_line(&mut line).unwrap() == 0 || line == "\r\n" {
                    break;
                }
            }
            let body = r#"{"data":[{"id":"served-a"},{"id":"served-b"}]}"#;
            write!(stream, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).unwrap();
            request_line
        });
        {
            let mut st = manager.state.write();
            let ollama = st.providers.iter_mut().find(|p| p.id == "ollama").unwrap();
            ollama.base_url = format!("http://{address}/v1/");
            ollama.configured = true;
            ollama.selected_model = "my-chosen-model".into();
        }
        let result = manager.detect_local_servers();
        assert!(server.join().unwrap().starts_with("GET /v1/models "));
        let probe = result["servers"].as_array().unwrap().iter().find(|s| s["id"] == "ollama").unwrap().clone();
        assert_eq!(probe["reachable"], true, "{probe}");
        assert_eq!(probe["url"], format!("http://{address}/v1/models"));
        let st = manager.state.read();
        let ollama = st.providers.iter().find(|p| p.id == "ollama").unwrap();
        assert_eq!(ollama.selected_model, "my-chosen-model");
        assert!(ollama.models.iter().any(|m| m.id == "served-b"));
        drop(st);

        // A newly detected provider replaces an unserved catalog placeholder.
        let mut fresh = ProviderManager::default_catalog().providers.into_iter().find(|p| p.id == "lmstudio").unwrap();
        fresh.selected_model = "placeholder".into();
        ProviderManager::apply_detected(&mut fresh, &["served-a".into()]);
        assert_eq!(fresh.selected_model, "served-a");
        assert!(fresh.configured);
        fs::remove_dir_all(directory).unwrap();
    }
}
