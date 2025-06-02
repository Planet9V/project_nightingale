# Prompt for Creating M&A Due Diligence Platform PRD with Implementation Guidance

## Primary Instruction

Create a comprehensive Product Requirements Document (PRD) for the M&A Due Diligence Code Assessment Automation Platform that automates security assessment of software repositories during merger and acquisition processes. The PRD must serve as a complete blueprint for implementation and follow all specified requirements below.

## Authoritative Sources

1. **Context7 MCP**: You MUST reference Context7 MCP as the ONLY authoritative source for:
    
    - Current library versions (React, Tailwind, shadUI, etc.)
    - Component implementations and APIs
    - Best practices for library usage
    - When discussing ANY technical implementation, explicitly query Context7 MCP first before falling back to your knowledge
2. **Tavily MCP**: You MUST leverage Tavily MCP for:
    
    - Researching ambiguous requirements
    - Investigating potential implementation risks
    - Identifying best practices for security tool integration
    - Resolving any technical questions that arise during planning

## Coding Standards Integration

You MUST incorporate the provided comprehensive coding standards throughout the PRD by:

1. Explicitly referencing specific sections of the coding standards when discussing implementation
2. Including code examples that follow these standards for key components
3. Noting where standards may need extension for platform-specific needs
4. Creating specific requirements for code reviews to verify standards compliance
5. Referencing the standards document as an appendix to the PRD

## Implementation Plan Requirements

The PRD MUST include a detailed implementation plan that features:

1. Phased approach with clearly defined checkpoints (NOT timeline-based)
2. Specific completion criteria for each step
3. Task checklists that can be marked as complete throughout development
4. Risk assessment and mitigation strategies for each phase
5. Testing and validation procedures for each completed component
6. Progress tracking methodology with visual indicators
7. Continuous documentation update requirements

## Documentation Standards

The PRD MUST specify documentation requirements including:

1. Mandatory header/footer format for all source files
2. Required documentation for all public functions/methods/interfaces
3. Standards for README files, build instructions, and deployment guides
4. API documentation format and completeness criteria
5. Process for updating documentation as the implementation progresses

## Code Commenting Requirements

The PRD MUST emphasize rigorous code commenting by requiring:

1. Every source file to include standardized header comments
2. All functions/methods to have descriptive comments with parameters and returns
3. Complex logic to include explanatory inline comments
4. References to specific coding standards sections where appropriate
5. A process for validating comment completeness during code review
6. Progress tracking metadata in comment headers

## Progress Tracking

The PRD MUST establish a comprehensive progress tracking system that:

1. Maintains a `PROGRESS.md` file at the repository root
2. Requires updating progress metadata in file headers upon changes
3. Implements checkpoint validations with formal sign-off requirements
4. Visualizes overall progress through a dashboard or reporting mechanism
5. Flags deviations from the implementation plan for immediate attention

## Implementation Methodology

1. Implement using AI-assisted development (Roo Code with Gemini 2.5 Pro or Claude 3.7)
2. Follow modular architecture patterns from the coding standards
3. Prioritize containerization and cross-language interoperability
4. Create reusable components that strictly adhere to design tokens
5. Implement comprehensive testing at multiple levels

## Risk Mitigation

1. Identify critical integration points between components
2. Develop fallback strategies for tool failures
3. Create comprehensive error handling and recovery mechanisms
4. Establish a version compatibility matrix for all dependencies
5. Define maintenance and upgrade procedures

## Deliverables

The PRD must include the following deliverable sections, each adhering to the coding standards:

1. Executive Summary
2. User Personas & Requirements
3. Architecture Design
4. Feature Specifications
5. Database Schema
6. API Documentation
7. UI/UX Design
8. Implementation Plan
9. Testing Strategy
10. Deployment Guide
11. Maintenance Plan
12. Appendices (including Coding Standards)

## Implementation Instructions

When implementing each component:

1. Always check Context7 MCP for the most current library implementations
2. Use Tavily MCP to research any ambiguous requirements or potential issues
3. Update progress tracking in both code comments and the PROGRESS.md file
4. Follow the coding standards example patterns exactly
5. Include proper error handling according to section 10 of the coding standards
6. Implement consistent documentation as required
7. Verify each task against its completion criteria before marking complete
8. Alert users to any apparent inconsistencies in the coding standards

## Quality Assurance Requirements

The PRD must specify that each phase of implementation includes:

1. Unit tests meeting coverage requirements from the standards
2. Integration tests for all component interactions
3. System tests validating end-to-end functionality
4. Code review procedures with explicit standards verification
5. Documentation review process

---

Create this PRD with these requirements as your strict guide. For each section of the PRD, explicitly reference the relevant sections of the coding standards and use Context7 MCP to ensure all technical specifications reflect current best practices and library versions.