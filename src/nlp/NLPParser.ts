import { config } from "../config/settings";
import type { NLPPrompt, SIEMQuery } from "../config/schema";
import { PROMPT_TEMPLATES } from "./PromptTemplates";

export class NLPParser {
  private async callOpenAI(prompt: NLPPrompt): Promise<string> {
    const response = await fetch("https://api.openai.com/v1/chat/completions", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${config.api.openai.apiKey}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        model: config.api.openai.model,
        messages: [
          { role: "system", content: prompt.system },
          { role: "user", content: prompt.user },
        ],
        max_tokens: config.api.openai.maxTokens,
        temperature: 0.1,
      }),
    });

    if (!response.ok) {
      throw new Error(`OpenAI API error: ${response.statusText}`);
    }

    const data = await response.json();
    return data.choices[0].message.content;
  }

  private async callGemini(prompt: NLPPrompt): Promise<string> {
    const response = await fetch(
      `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent`,
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-goog-api-key": config.api.gemini.apiKey,
        },
        body: JSON.stringify({
          contents: [
            {
              parts: [
                {
                  text: `${prompt.system}\n\n${prompt.user}`,
                },
              ],
            },
          ],
          generationConfig: {
            temperature: 0.1,
          },
        }),
      }
    );

    if (!response.ok) {
      throw new Error(`Gemini API error: ${response.statusText}`);
    }

    const data = await response.json();
    return data.candidates[0].content.parts[0].text;
  }

  async parseQuery(userQuery: string, context?: string): Promise<SIEMQuery> {
    const prompt: NLPPrompt = {
      system: PROMPT_TEMPLATES.system,
      user: PROMPT_TEMPLATES.queryGeneration(userQuery, context),
    };

    let response: string;

    response = await this.callGemini(prompt);
    const cleanResponse = response.replace("```json", "").replace("```", "");

    try {
      return JSON.parse(cleanResponse) as SIEMQuery;
    } catch {
      throw new Error("Failed to parse LLM response as SIEM query");
    }
  }

  async analyzeResults(query: string, results: any[]): Promise<string> {
    const prompt: NLPPrompt = {
      system: PROMPT_TEMPLATES.system,
      user: PROMPT_TEMPLATES.resultAnalysis(query, results),
    };
    return await this.callGemini(prompt);
  }
}
