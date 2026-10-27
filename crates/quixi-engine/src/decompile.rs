//! A separate text-completion specialist, driven by the main coding model.
use crate::QuixiEngine;
use anyhow::{bail, Context, Result};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{fs, path::{Path, PathBuf}};
use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Clone, Serialize, Deserialize)]
#[serde(default, rename_all="camelCase", deny_unknown_fields)]
pub struct Settings {
    pub enabled: bool,
    pub provider: String,
    pub model: String,
    pub profile: String,
    pub max_tokens: u32,
}
impl Default for Settings {
    fn default() -> Self { Self { enabled:false,provider:"custom".into(),model:String::new(),profile:"llm4-ref".into(),max_tokens:1024 } }
}
pub struct DecompileAssistant {
    path: PathBuf,
    settings: Mutex<Settings>,
    operation: Mutex<()>,
    last_success: Mutex<Option<Value>>,
    provider_generation: AtomicU64,
}
fn validate(settings: &Settings) -> Result<()> {
    if !matches!(settings.profile.as_str(),"llm4-ref"|"llm4-end") { bail!("Choose LLM4Decompile Ref (pseudo-code) or End (assembly)"); }
    if !(1..=2048).contains(&settings.max_tokens) { bail!("Output tokens must be between 1 and 2048"); }
    if settings.enabled && (settings.provider.trim().is_empty() || settings.model.trim().is_empty()) { bail!("Choose the specialist provider and its exact model ID"); }
    Ok(())
}
pub fn prompt(input: &str) -> Result<String> {
    let input = input.trim();
    if input.is_empty() || input.chars().count()>16_000 || input.contains('\0') { bail!("Provide one nonempty function of at most 16,000 characters; the endpoint enforces its token context limit"); }
    // Both upstream Ref V2 and End V1.5 use this exact wrapper, even for pseudo-code.
    Ok(format!("# This is the assembly code:\n{input}\n# What is the source code?\n"))
}
fn extract(value: &Value, keys: &[&str], depth: usize) -> Option<String> {
    if depth>16 { return None; }
    match value {
        Value::Object(map) => {
            for key in keys {
                if let Some(text) = map.get(*key).and_then(Value::as_str).filter(|s|!s.trim().is_empty()) { return Some(text.to_owned()); }
            }
            map.values().find_map(|v|extract(v,keys,depth+1))
        }
        Value::Array(values) => values.iter().find_map(|v|extract(v,keys,depth+1)),
        _ => None,
    }
}
fn input_from_record(record: &Value, profile: &str) -> Result<String> {
    let response = quixi_mcp::rea::payload(&record["response"]);
    let keys: &[&str] = if profile=="llm4-ref" { &["pseudocode","pseudo_code","decompiled_code"] } else { &["assembly"] };
    if let Some(text) = extract(&response,keys,0) { return Ok(text); }
    let tool = record["tool"].as_str().unwrap_or("");
    if (profile=="llm4-ref" && tool=="procedure_pseudo_code") || (profile=="llm4-end" && tool=="procedure_assembly") {
        if let Some(text) = response["normalized_result"].as_str() { return Ok(text.to_owned()); }
    }
    if record["kind"]=="imported-report" {
        return Ok(quixi_mcp::debugger::text_result(&record["response"]));
    }
    bail!("This record contains no compatible function text. Select decompiled pseudo-code for Ref, or prepared assembly for End; alternatively provide the reviewed function text.")
}
impl DecompileAssistant {
    pub fn new(data: &Path) -> Self {
        let path=data.join("decompile-assistant.json");
        let settings=fs::read(&path).ok().and_then(|b|serde_json::from_slice(&b).ok()).unwrap_or_default();
        Self {path,settings:Mutex::new(settings),operation:Mutex::new(()),last_success:Mutex::new(None),provider_generation:AtomicU64::new(0)}
    }
    pub fn enabled(&self) -> bool { self.settings.lock().enabled }
    pub fn provider_changed(&self, provider: &str) {
        if self.settings.lock().provider == provider {
            let mut last=self.last_success.lock();
            self.provider_generation.fetch_add(1,Ordering::AcqRel);
            *last=None;
        }
    }
    pub fn status(&self) -> Value {
        let last=self.last_success.lock().clone();
        json!({"settings":*self.settings.lock(),"busy":self.operation.is_locked(),"connected":last.is_some(),"lastSuccess":last,"transport":"text-completions","verification":"Model suggestions require independent checks"})
    }
    pub fn handle(&self, engine: &QuixiEngine, route: &str, body: &Value) -> Result<Value> {
        match route {
            "status" => Ok(self.status()),
            "configure" => {
                let _guard=self.operation.try_lock().context("Wait for the current specialist request to finish")?;
                let settings: Settings=serde_json::from_value(body["settings"].clone())?;
                validate(&settings)?;
                if !engine.provider_manager.state.read().providers.iter().any(|p|p.id==settings.provider && p.api_format=="openai" && p.auth_mode!="oauth") { bail!("Choose an OpenAI-compatible provider in Providers first"); }
                fs::write(&self.path,serde_json::to_vec_pretty(&settings)?)?;
                *self.settings.lock()=settings;
                *self.last_success.lock()=None;
                Ok(self.status())
            }
            "models" => {
                let provider=body["provider"].as_str().context("Choose a provider")?;
                let response=engine.provider_manager.specialist_request(provider,None)?;
                let models:Vec<_>=response["data"].as_array().context("Endpoint did not return a model list")?
                    .iter().filter_map(|m|m["id"].as_str()).take(2000).collect();
                engine.provider_manager.remember_models(provider,&models);
                Ok(json!({"provider":provider,"models":models,"llm4decompile":models.iter().filter(|m|m.to_lowercase().contains("llm4decompile")).collect::<Vec<_>>(),"note":"Advertised models; a successful completion establishes readiness."}))
            }
            "input" => {
                let id=body["recordId"].as_str().context("Select an evidence record")?;
                let record=engine.analysis.read_record(id)?;
                let profile=self.settings.lock().profile.clone();
                Ok(json!({"recordId":id,"input":input_from_record(&record,&profile)?}))
            }
            "assist" => self.assist(engine,body),
            _ => bail!("Unknown specialist operation"),
        }
    }
    pub fn assist(&self, engine: &QuixiEngine, body: &Value) -> Result<Value> {
        let _guard=self.operation.try_lock().context("A specialist request is already running")?;
        let settings=self.settings.lock().clone();
        validate(&settings)?;
        if !settings.enabled { bail!("Enable the decompilation specialist in Reverse engineering first"); }
        let id=body["recordId"].as_str().context("Provide the source evidence record ID")?;
        let source=engine.analysis.read_record(id)?;
        if source["failed"]==true || source["kind"]=="model-suggestion" { bail!("Use a successful original analysis record as the source"); }
        let target=source["target"].as_str().context("Source record has no target")?;
        let selected=engine.analysis.target.lock().clone();
        if selected.is_empty() || !target.eq_ignore_ascii_case(&selected) { bail!("Select the source record's artifact before requesting a suggestion"); }
        let supplied=body["input"].as_str().filter(|s|!s.trim().is_empty());
        let input=match supplied { Some(s)=>s.to_owned(),None=>input_from_record(&source,&settings.profile)? };
        let prompt=prompt(&input)?;
        let request=json!({"model":settings.model,"prompt":prompt,"max_tokens":settings.max_tokens,"temperature":0,"stream":false});
        let started=std::time::Instant::now();
        let generation=self.provider_generation.load(Ordering::Acquire);
        let response=engine.provider_manager.specialist_request(&settings.provider,Some(request));
        let response=match response {
            Ok(value) => match value.pointer("/choices/0/text").and_then(Value::as_str).filter(|s|!s.trim().is_empty()) {
                Some(code)=>json!({"structuredContent":{"decompiled_code":code,"requestedModel":settings.model,"returnedModel":value["model"],"finishReason":value["choices"][0]["finish_reason"],"usage":value["usage"],"verified":false,"complete":value["choices"][0]["finish_reason"]=="stop","limitations":["Generated suggestion, not original source or observed behaviour.","LLM4Decompile's published scope is Linux x86-64/GCC. Windows targets require separate validation.","Compile and test the output before relying on it."]}}),
                None=>json!({"isError":true,"content":[{"type":"text","text":"The specialist returned no completion text. This endpoint must support /completions with a raw prompt."}]}),
            },
            Err(error)=>json!({"isError":true,"content":[{"type":"text","text":error.to_string()}]}),
        };
        {
            let mut last=self.last_success.lock();
            *last=if response["isError"]==true || self.provider_generation.load(Ordering::Acquire)!=generation {None} else {Some(json!({"provider":settings.provider,"model":settings.model,"checkedAt":chrono::Utc::now().to_rfc3339()}))};
        }
        engine.analysis.save_external("llm4decompile","model-suggestion","decompile_assist",
            json!({"recordId":id,"provider":settings.provider,"model":settings.model,"profile":settings.profile,"maxTokens":settings.max_tokens}),target,response,
            json!({"sourceRecordId":id,"input":input,"inputSha256":format!("{:x}",Sha256::digest(input.as_bytes())),"inputOrigin":if supplied.is_some(){"supplied-function"}else{"extracted-from-record"},"elapsedMs":started.elapsed().as_millis(),"verified":false}))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn follows_upstream_prompt_and_rejects_empty_or_unbounded_input() {
        assert_eq!(prompt(" int add(int a,int b){return a+b;} ").unwrap(),"# This is the assembly code:\nint add(int a,int b){return a+b;}\n# What is the source code?\n");
        assert!(prompt("").is_err());assert!(prompt(&"a".repeat(16001)).is_err());
    }
    #[test]
    fn input_requires_the_chosen_representation() {
        let r=json!({"tool":"procedure_pseudo_code","response":{"structuredContent":{"normalized_result":"int f(void){return 1;}"}}});
        assert_eq!(input_from_record(&r,"llm4-ref").unwrap(),"int f(void){return 1;}");
        assert!(input_from_record(&r,"llm4-end").is_err());
        assert!(validate(&Settings{enabled:true,..Settings::default()}).is_err());
        assert!(validate(&Settings{max_tokens:9000,..Settings::default()}).is_err());
    }
}
