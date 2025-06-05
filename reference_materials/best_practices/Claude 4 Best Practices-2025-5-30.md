---
title: "Claude 4 prompt engineering best practices"
url: "https://docs.anthropic.com/en/docs/build-with-claude/prompt-engineering/claude-4-best-practices"
clipdate: "2025-05-30T18:01:55-05:00"
author: "Anthropic"
type: "article"
publisher: "docs.anthropic.com"
published: "N/A"
people: []
organizations: [{\\"id\\": \\"anthropic-1\
concepts: [{\\"id\\": \\"prompt-engineering-1\
products: []
transactions: []
events: []
locations: []
tags: ["article", [\\"prompt engineering\]
relationships: [
  {"type": "schema:author", "target": "Anthropic"},
  {"type": "schema:publisher", "target": "docs.anthropic.com"},
  {"type": "schema:mentions", "targets": []},
  {"type": "schema:memberOf", "source": []},
  {"type": "schema:about", "targets": [\\"prompt-engineering-1\},
  {"type": "schema:mentions", "qualifier": "organization", "targets": [\\"anthropic-1\\"]},
  {"type": "schema:mentions", "qualifier": "product", "targets": []},
  {"type": "schema:mentions", "qualifier": "transaction", "targets": []},
  {"type": "schema:mentions", "qualifier": "event", "targets": []},
  {"type": "schema:mentions", "qualifier": "location", "targets": []},
  {"type": "schema:isRelatedTo", "targets": [\\"Prompt Engineering Techniques\}
]
---

# Claude 4 prompt engineering best practices

> [!article]
> Source: [Claude 4 prompt engineering best practices](https://docs.anthropic.com/en/docs/build-with-claude/prompt-engineering/claude-4-best-practices)
> Author: Anthropic
> Publisher: docs.anthropic.com
> Date: N/A

## Summary

> This document provides prompt engineering best practices for Claude 4 models, emphasizing clear and explicit instructions, adding context, and vigilance with examples. It covers controlling response formats, leveraging thinking capabilities, optimizing parallel tool calling, reducing file creation in agentic coding, and enhancing visual code generation. It also includes migration considerations from Sonnet 3.7 to Claude 4.

## Key Points

- Be explicit with instructions.
- Add context to improve performance.
- Be vigilant with examples and details.
- Tell Claude what to do instead of what not to do.
- Use XML format indicators.
- Match prompt style to desired output.
- Leverage thinking and interleaved thinking capabilities.
- Optimize parallel tool calling.
- Reduce file creation in agentic coding.
- Enhance visual and frontend code generation.

## Entities


### People Mentioned





### Organizations Referenced

# Anthropic
Type: company



### Key Concepts

# Prompt Engineering
Brief description: Techniques for crafting effective prompts to guide language models.

# Claude 4
Brief description: A new generation of Claude models with improved instruction following.

# Tool Calling
Brief description: The ability of language models to use external tools to perform tasks.

# Extended Thinking
Brief description: Claude's ability to reflect and plan before taking action.



### Products/Equipment





### Transactions





### Events






### Locations




## Related Content

[[Prompt Engineering]], [[Large Language Models]], [[Claude (AI)]]

## Content

This guide provides specific prompt engineering techniques for Claude 4 models (Opus 4 and Sonnet 4) to help you achieve optimal results in your applications. These models have been trained for more precise instruction following than previous generations of Claude models.

## General principles

### Be explicit with your instructions

Claude 4 models respond well to clear, explicit instructions. Being specific about your desired output can help enhance results. Customers who desire the “above and beyond” behavior from previous Claude models might need to more explicitly request these behaviors with Claude 4.

### Add context to improve performance

Providing context or motivation behind your instructions, such as explaining to Claude why such behavior is important, can help Claude 4 better understand your goals and deliver more targeted responses.

Claude is smart enough to generalize from the explanation.

### Be vigilant with examples & details

Claude 4 models pay attention to details and examples as part of instruction following. Ensure that your examples align with the behaviors you want to encourage and minimize behaviors you want to avoid.

## Guidance for specific situations

### Control the format of responses

There are a few ways that we have found to be particularly effective in seering output formatting in Claude 4 models:

1. **Tell Claude what to do instead of what not to do**
	- Instead of: “Do not use markdown in your response”
	- Try: “Your response should be composed of smoothly flowing prose paragraphs.”
2. **Use XML format indicators**
	- Try: “Write the prose sections of your response in <smoothly\_flowing\_prose\_paragraphs> tags.”
3. **Match your prompt style to the desired output**
	The formatting style used in your prompt may influence Claude’s response style. If you are still experiencing steerability issues with output formatting, we recommend as best as you can matching your prompt style to your desired output style. For exmaple, removing markdown from your prompt can reduce the volume of markdown in the output.

### Leverage thinking & interleaved thinking capabilities

Claude 4 offers thinking capabilities that can be especially helpful for tasks involving reflection after tool use or complex multi-step reasoning. You can guide its initial or interleaved thinking for better results.

Example prompt

For more information on thinking capabilities, see [Extended thinking](https://docs.anthropic.com/en/docs/build-with-claude/extended-thinking).

### Optimize parallel tool calling

Claude 4 models excel at parallel tool execution. They have a high success rate in using parallel tool calling without any prompting to do so, but some minor prompting can boost this behavior to ~100% parallel tool use success rate. We have found this prompt to be most effective:

Sample prompt for agents

### Reduce file creation in agentic coding

Claude 4 models may sometimes create new files for testing and iteration purposes, particularly when working with code. This approach allows Claude to use files, especially python scripts, as a ‘temporary scratchpad’ before saving its final output. Using temporary files can improve outcomes particularly for agentic coding use cases.

If you’d prefer to minimize net new file creation, you can instruct Claude to clean up after itself:

Sample prompt

### Enhance visual and frontend code generation

For frontend code generation, you can steer Claude 4 models to create complex, detailed, and interactive designs by providing explicit encouragement:

Sample prompt

You can also improve Claude’s frontend performance in specific areas by providing additional modifiers and details on what to focus on:

- “Include as many relevant features and interactions as possible”
- “Add thoughtful details like hover states, transitions, and micro-interactions”
- “Create an impressive demonstration showcasing web development capabilities”
- “Apply design principles: hierarchy, contrast, balance, and movement”

## Migration considerations

When migrating from Sonnet 3.7 to Claude 4:

1. **Be specific about desired behavior**: Consider describing exactly what you’d like to see in the output.
2. **Frame your instructions with modifiers**: Adding modifiers that encourage Claude to increase the quality and detail of its output can help better shape Claude’s performance. For example, instead of “Create an analytics dashboard”, use “Create an analytics dashboard. Include as many relevant features and interactions as possible. Go beyond the basics to create a fully-featured implementation.”
3. **Request specific features explicitly**: Animations and interactive elements should be requested explicitly when desired.
