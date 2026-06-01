const OpenAI = require('openai');
const logger = require('../utils/logger');

let openaiClient = null;

function getClient() {
  if (!openaiClient) {
    if (!process.env.AI_API_KEY) {
      throw new Error('AI_API_KEY environment variable is not set');
    }
    openaiClient = new OpenAI({
      apiKey: process.env.AI_API_KEY,
      // Support OpenAI-compatible endpoints (e.g. Groq, Together, etc.)
      baseURL: process.env.AI_BASE_URL || 'https://api.openai.com/v1',
    });
  }
  return openaiClient;
}

const DEFAULT_MODEL = process.env.AI_MODEL || 'gpt-4o-mini';

/**
 * Analyse source code for security vulnerabilities.
 * Returns a structured JSON response.
 */
async function analyseCode({ code, language, filePath }) {
  const client = getClient();

  const systemPrompt = `You are an expert security code reviewer specialising in finding vulnerabilities in ${language} code.
Your task is to analyse the provided code and identify security issues.

Return ONLY a valid JSON object with this exact structure:
{
  "vulnerabilities": [
    {
      "id": "unique_id",
      "severity": "critical|high|medium|low|info",
      "category": "injection|xss|insecure-deserialization|broken-auth|sensitive-data|xxe|broken-access|security-misconfig|dependency|cryptography|other",
      "title": "Short descriptive title",
      "description": "Detailed explanation of the vulnerability",
      "line": <line_number_or_null>,
      "cwe": "CWE-xxx",
      "owasp": "A0x:2021",
      "recommendation": "How to fix this issue",
      "code_snippet": "The vulnerable code snippet"
    }
  ],
  "summary": {
    "total": <count>,
    "critical": <count>,
    "high": <count>,
    "medium": <count>,
    "low": <count>,
    "info": <count>
  },
  "secure_score": <0-100>,
  "language": "${language}",
  "analysed_at": "<ISO timestamp>"
}`;

  const userPrompt = `File: ${filePath || 'unknown'}
Language: ${language}

\`\`\`${language}
${code}
\`\`\`

Analyse this code for ALL security vulnerabilities including but not limited to:
- Injection attacks (SQL, command, LDAP, XPath)
- Cross-Site Scripting (XSS)
- Insecure cryptography or hashing
- Hard-coded credentials or API keys
- Insecure direct object references
- Broken authentication/session management
- Sensitive data exposure
- Security misconfigurations
- Prototype pollution
- Path traversal
- Unsafe deserialization
- Race conditions
- Memory leaks that can be exploited`;

  logger.info(`Analysing ${language} code (${code.length} chars) with AI model ${DEFAULT_MODEL}`);

  const response = await client.chat.completions.create({
    model: DEFAULT_MODEL,
    messages: [
      { role: 'system', content: systemPrompt },
      { role: 'user', content: userPrompt },
    ],
    temperature: 0.1,
    response_format: { type: 'json_object' },
    max_tokens: 4096,
  });

  const rawContent = response.choices[0].message.content;

  try {
    const parsed = JSON.parse(rawContent);
    parsed.analysed_at = new Date().toISOString();
    return parsed;
  } catch (e) {
    logger.error('Failed to parse AI response as JSON', { rawContent });
    throw new Error('AI returned invalid JSON response');
  }
}

/**
 * Generate an embedding vector for a text (for vector search).
 */
async function generateEmbedding(text) {
  const client = getClient();
  const response = await client.embeddings.create({
    model: 'text-embedding-3-small',
    input: text.slice(0, 8192), // Token limit
  });
  return response.data[0].embedding;
}

/**
 * Chat completion for the security assistant.
 */
async function securityChat({ messages, context }) {
  const client = getClient();

  const systemMsg = {
    role: 'system',
    content: `You are SecureGuard AI, an expert cybersecurity assistant integrated into VS Code.
You help developers understand and fix security vulnerabilities in their code.
Be concise, practical, and always provide code examples when suggesting fixes.
${context ? `\nContext from current scan:\n${JSON.stringify(context, null, 2)}` : ''}`,
  };

  const response = await client.chat.completions.create({
    model: DEFAULT_MODEL,
    messages: [systemMsg, ...messages],
    temperature: 0.3,
    max_tokens: 2048,
    stream: false,
  });

  return {
    content: response.choices[0].message.content,
    usage: response.usage,
  };
}

module.exports = { analyseCode, generateEmbedding, securityChat };
