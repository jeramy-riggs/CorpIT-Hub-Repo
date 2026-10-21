// ai-domains.js — curated shadow-AI hostname list (v2.0 tighter)
// Match rules: pure hostname (protocol/path/port stripped) — exact OR domain-suffix.
// No path entries. No substring matches. False-positive resistant.
'use strict';
const AI_DOMAINS = [
  // OpenAI / ChatGPT
  'openai.com','chatgpt.com','oaistatic.com','oaiusercontent.com','sora.com',
  // Anthropic / Claude
  'anthropic.com','claude.ai','claudeusercontent.com',
  // Google AI (specific subdomains only — google.com root would over-match)
  'gemini.google.com','bard.google.com','aistudio.google.com','notebooklm.google.com',
  'generativelanguage.googleapis.com','vertexai.googleapis.com','labs.google.com',
  'deepmind.com','deepmind.google',
  // Microsoft Copilot (specific — bing.com root would over-match)
  'copilot.microsoft.com','declarative-copilot.microsoft.com',
  // Meta AI
  'meta.ai','llama.meta.com','llama.com',
  // xAI / Grok
  'x.ai','grok.com',
  // Perplexity / You / Phind / Komo / Andi
  'perplexity.ai','pplx.ai','you.com','phind.com','komo.ai','andi.ai',
  // Frontier + open-source hosting
  'huggingface.co','hf.co','together.ai','together.xyz','replicate.com','replicate.delivery',
  'groq.com','fireworks.ai','openrouter.ai','anyscale.com','runpod.io','modal.com','baseten.co',
  'novita.ai','deepinfra.com','lepton.ai','banana.dev','beam.cloud','octo.ai',
  // Mistral / Cohere / AI21 / Databricks / IBM / NVIDIA
  'mistral.ai','codestral.mistral.ai','cohere.com','cohere.ai','ai21.com','studio.ai21.com',
  'watsonx.ai','build.nvidia.com',
  // Chinese frontier
  'deepseek.com','deepseek.ai','moonshot.cn','qwenlm.ai','chatglm.cn','minimaxi.com','zhipuai.cn',
  // Character / companion / consumer chat
  'character.ai','characterai.io','janitorai.com','crushon.ai','spicychat.ai','joyland.ai',
  'chai-research.com','replika.ai','pi.ai','inflection.ai',
  // Aggregators
  'poe.com','flowgpt.com','hix.ai','forefront.ai','lmarena.ai','arena.lmsys.org',
  'chatbotui.com','chathub.gg','gigachat.com',
  // Writing / marketing
  'grammarly.com','quillbot.com','copy.ai','jasper.ai','writer.com','writesonic.com','rytr.me',
  'sudowrite.com','wordtune.com','narrato.io','frase.io','anyword.com','simplified.com','notion.ai',
  // Coding
  'cursor.com','cursor.sh','codeium.com','windsurf.dev','codegpt.co','tabnine.com',
  'continue.dev','sweep.dev','aider.chat','cody.dev',
  'codestory.ai','cline.bot','bolt.new','v0.dev','v0.app','lovable.dev',
  'devin.ai','cognition.ai','tabby.tabbyml.com',
  // Image/video/audio gen
  'midjourney.com','runwayml.com','runway.team','pika.art','pikalabs.org','stability.ai',
  'stablediffusionweb.com','leonardo.ai','ideogram.ai','artbreeder.com','clipdrop.co',
  'krea.ai','recraft.ai',
  'suno.ai','suno.com','udio.com','elevenlabs.io','elevenlabs.com','play.ht','murf.ai',
  'wellsaidlabs.com','descript.com','synthesia.io','heygen.com','d-id.com','hedra.com',
  'captions.ai','opus.pro','klingai.com','luma.ai','luma-ai.com','viggle.ai','haiper.ai',
  // Research AI
  'genspark.ai','iask.ai','consensus.app','elicit.com','scite.ai','scholarcy.com',
  'openevidence.com','undermind.ai',
  // Meeting / voice / transcription
  'otter.ai','fireflies.ai','tldv.io','gong.io','fathom.video','avoma.com','krisp.ai',
  'tactiq.io','grain.co','notiv.com','airgram.io',
  // Agents / RAG / builders
  'flowise.ai','langflow.org','stack-ai.com','vellum.ai','glean.com',
  'moveworks.com','articulai.com','sana.ai','harveyai.com','harvey.ai',
  // Local model runners
  'ollama.ai','ollama.com','lmstudio.ai','gpt4all.io','jan.ai','msty.app','openwebui.com',
  // Dev / prompt / eval
  'promptbase.com','langsmith.com','langchain.com','llamaindex.ai','helicone.ai',
  'wandb.ai','braintrust.dev'
];
const AI_SET = new Set(AI_DOMAINS.map(d => d.toLowerCase()));
function extractHost(input) {
  if (!input) return '';
  var s = String(input).toLowerCase().trim();
  s = s.replace(/^https?:\/\//, '');
  var slash = s.indexOf('/'); if (slash >= 0) s = s.slice(0, slash);
  var colon = s.indexOf(':'); if (colon >= 0) s = s.slice(0, colon);
  var q = s.indexOf('?'); if (q >= 0) s = s.slice(0, q);
  return s;
}
function hostMatchesAI(input) {
  var h = extractHost(input);
  if (!h) return false;
  if (AI_SET.has(h)) return true;
  // F24 (2026-10-21): the host is sender-controlled and can be megabytes long; rebuilding every suffix
  // with split/slice/join was O(labels^2). Only the last 253 chars (max DNS name) can hold a listed
  // suffix, so match on that window and walk dots with indexOf/substring. Same results as before:
  // every suffix after a dot except the bare last label.
  if (h.length > 253) h = h.slice(-253);
  for (var i = h.indexOf('.'); i >= 0; i = h.indexOf('.', i + 1)) {
    if (h.indexOf('.', i + 1) < 0) break;
    if (AI_SET.has(h.substring(i + 1))) return true;
  }
  return false;
}
module.exports = { AI_DOMAINS: AI_DOMAINS, hostMatchesAI: hostMatchesAI, extractHost: extractHost };
