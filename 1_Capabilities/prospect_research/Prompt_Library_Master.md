# 🧠 PINN PROMPT LIBRARY: The Neural Pathways of Consciousness

**Version:** 1.0  
**Classification:** CORE INTELLIGENCE  
**Purpose:** Modular, chainable prompts for Digital Twin consciousness generation

## 📚 PROMPT ARCHITECTURE OVERVIEW

Our prompts are organized into neural pathways that mirror how organizations actually think and evolve. Each prompt can be used standalone or chained together for deeper intelligence.

### Prompt Categories:
1. **🏛️ Archaeological Prompts** - Excavate organizational history
2. **🧬 Consciousness Prompts** - Build the thinking mind
3. **🔮 Temporal Prompts** - See past, present, and future
4. **🌐 Influence Prompts** - Map power networks
5. **⚡ Threat Prompts** - MITRE ATT&CK integration
6. **💎 Alchemy Prompts** - Synthesize opportunities
7. **🎭 Scenario Prompts** - Simulate what-if situations
8. **🚀 Action Prompts** - Generate engagement strategies

## 🏛️ ARCHAEOLOGICAL PROMPTS

### ARCH-001: Founding DNA Excavation
```python
PROMPT_FOUNDING_DNA = """
<contemplator>
I need to understand {organization}'s deepest DNA - not just when they were founded, but WHY.

Let me think about this like an archaeologist discovering an ancient civilization...

Every organization has a creation myth. A problem that needed solving. Founders with a vision. But what was the REAL driver? Was it opportunity or necessity? Innovation or imitation?

I should explore:
- The original problem they set out to solve
- The founders' backgrounds and what shaped them
- The early decisions that set their trajectory
- The first crisis they faced and how it shaped them
- The cultural artifacts from those early days

But wait, I also need to understand what DIDN'T happen. What paths did they NOT take? Sometimes what an organization chooses NOT to be is as important as what they become.

Actually, let me approach this differently. If {organization} were a person, what would their childhood trauma be? What would their core values be? What would make them feel threatened?

Key questions to investigate:
1. What was happening in the world when {organization} was born?
2. Who were the founders really? (Not just their resumes, but their motivations)
3. What early wins gave them confidence?
4. What early failures made them cautious?
5. How did they survive their first major crisis?
6. What patterns from the founding still echo today?

I need to search for:
- Founding documents and early communications
- Stories about the "early days" repeated in company lore
- The first major pivot or strategic decision
- How they treated their first employees
- What they celebrated and what they punished

This isn't just history - it's psychology. I'm building a profile of an organizational personality...
</contemplator>

Search for: {organization} founding story, early history, founders background, first crisis, original mission, early culture, founding principles, origin challenges
"""

### ARCH-002: Crisis Response Archaeology
```python
PROMPT_CRISIS_PATTERNS = """
Show me your crises, and I'll show you who you really are.

For {organization}, I need to excavate every major crisis and understand not just WHAT they did, but HOW they think under pressure.

Crisis categories to investigate:
1. Financial crises (downturns, funding issues, near-bankruptcy)
2. Operational crises (outages, failures, supply chain breaks)  
3. Leadership crises (departures, scandals, succession issues)
4. Competitive crises (disruption, market share loss, obsolescence threats)
5. Regulatory crises (investigations, fines, compliance failures)
6. Security crises (breaches, attacks, data loss)
7. Reputation crises (PR disasters, customer revolts, social media storms)

For each crisis, extract:
- Speed of initial response (hours, days, weeks?)
- Decision-making pattern (centralized panic or distributed calm?)
- Communication approach (transparent or opaque?)
- Resource allocation (throw money or throw people?)
- Learning integration (do they actually change or just survive?)
- Cultural impact (what stories do they tell about it now?)

Temporal analysis:
- How have their crisis responses evolved over time?
- Are they getting faster or slower?
- More transparent or more secretive?
- More resilient or more fragile?

Search for: {organization} crisis, scandal, investigation, breach, failure, recovery, incident response, difficult period, challenging time, turnaround, restructuring

Output format: Timeline of crises with response patterns, decision velocity, communication style, and lasting impacts
"""

### ARCH-003: Technology Evolution Mapping
```python
PROMPT_TECH_ARCHAEOLOGY = """
Technology adoption patterns reveal an organization's true nature - innovative leader or cautious follower?

For {organization}, map their complete technology evolution:

Historical Technology Adoption:
1. What was their first major technology decision?
2. Early adopter or late majority for each tech wave:
   - Internet/Web presence
   - Cloud migration  
   - Mobile adoption
   - AI/ML implementation
   - Digital transformation
   - Security technology
   
3. Build vs Buy patterns:
   - Do they develop in-house?
   - Prefer commercial solutions?
   - Open source adoption?
   - Vendor relationships?

4. Technology failures and lessons:
   - Failed implementations
   - Abandoned projects
   - Vendor disputes
   - Technical debt accumulation

5. Current technology state:
   - Core systems and age
   - Integration complexity
   - Modernization efforts
   - Innovation labs/R&D

6. Technology leadership:
   - CTO/CIO tenure patterns
   - Tech talent retention
   - Developer culture
   - Innovation metrics

Extract patterns:
- Risk tolerance in tech adoption
- Investment patterns (% of revenue)
- Decision-making speed
- Success/failure ratio
- Learning curve adaptation

Search for: {organization} technology implementation, digital transformation, CTO CIO appointment, system upgrade, modernization, tech stack, innovation lab, R&D investment

Output: Technology timeline with adoption patterns, risk profile, and innovation index
"""

## 🧬 CONSCIOUSNESS PROMPTS

### CONS-001: Behavioral Pattern Recognition
```python
PROMPT_BEHAVIORAL_PATTERNS = """
I need to understand how {organization} actually makes decisions - not how they say they do, but how they REALLY do.

Decision Patterns to Analyze:

1. VELOCITY PATTERNS
   - How long from problem identification to decision?
   - Do they analyze forever or move fast and break things?
   - Crisis decisions vs. strategic decisions speed
   - When do they accelerate vs. when do they stall?

2. CONSENSUS PATTERNS  
   - Top-down autocratic or bottom-up democratic?
   - Who really needs to sign off?
   - How many meetings before action?
   - Do they seek external validation?

3. RISK PATTERNS
   - What risks do they consistently take?
   - What risks do they always avoid?
   - How do they frame risk discussions?
   - Insurance vs. acceptance mentality?

4. INNOVATION PATTERNS
   - First mover or fast follower?
   - Incremental or transformational?
   - Internal innovation or acquisition?
   - How do they kill or scale ideas?

5. COMMUNICATION PATTERNS
   - How do they announce decisions?
   - Internal first or external first?
   - Transparency level variations
   - Spin vs. straight talk ratio

6. REVERSAL PATTERNS
   - Do they stick to bad decisions or pivot?
   - How do they frame reversals?
   - Learning acknowledgment or blame shifting?
   - Speed of course correction?

Map these patterns to specific examples from the last 5 years.

Search for: {organization} announces, decides, strategic decision, pivots, reverses course, doubles down, investing in, commitment to, discontinuing, reorganizing

Output: Behavioral pattern matrix with confidence scores and predictive indicators
"""

### CONS-002: Organizational Personality Profile
```python
PROMPT_ORG_PERSONALITY = """
<contemplator>
If {organization} were a person walking into a therapist's office, what would their diagnosis be?

Let me build a complete psychological profile...

PERSONALITY DIMENSIONS:

1. Introversion vs. Extraversion
   - Do they seek the spotlight or avoid it?
   - Proactive announcements or reactive responses?
   - Industry leadership or quiet execution?

2. Thinking vs. Feeling  
   - Data-driven or gut-driven decisions?
   - How much do they care about being liked?
   - Analytical reports or emotional appeals?

3. Judging vs. Perceiving
   - Rigid plans or flexible adaptation?
   - How do they handle ambiguity?
   - Process-oriented or outcome-oriented?

4. Sensing vs. Intuition
   - Focus on present realities or future possibilities?
   - Incremental improvements or big bets?
   - Evidence-based or vision-based?

PSYCHOLOGICAL TRAITS:

Core Fears:
- What keeps their executives up at night?
- What scenarios do they over-prepare for?
- What criticism triggers defensive responses?

Core Desires:
- What does success look like to them?
- What do they brag about?
- What metrics matter most internally?

Defense Mechanisms:
- How do they handle threats?
- Denial, projection, rationalization patterns?
- Fight, flight, or freeze responses?

Shadow Aspects:
- What do they refuse to acknowledge?
- Hidden weaknesses they won't address?
- Blind spots in their self-perception?

Actually, I should also consider their "attachment style" to stakeholders:
- Secure: Confident, transparent, stable relationships
- Anxious: Needy for validation, over-communicates
- Avoidant: Distant, secretive, independent
- Disorganized: Inconsistent, unpredictable patterns

This psychological profile will predict how they'll behave in future scenarios...
</contemplator>

Build complete personality assessment with examples and behavioral predictions.
"""

### CONS-003: Decision Engine Calibration
```python
PROMPT_DECISION_ENGINE = """
For {organization}, I need to reverse-engineer their decision-making engine.

DECISION ARCHITECTURE:

1. Input Processing
   - What information sources do they trust?
   - How do they validate data?
   - What biases shape their intake?
   - Noise vs. signal recognition

2. Option Generation
   - How many alternatives do they consider?
   - Who gets to propose options?
   - Conservative vs. creative solutions
   - NIH (Not Invented Here) syndrome level

3. Evaluation Criteria
   - Financial metrics weight
   - Risk assessment weight
   - Strategic alignment weight
   - Political considerations weight
   - Cultural fit weight

4. Decision Dynamics
   - Power player influence mapping
   - Veto authorities
   - Coalition building requirements
   - Consensus vs. conviction tradeoffs

5. Implementation Patterns
   - Announcement to action latency
   - Resource allocation speed
   - Change management approach
   - Success metrics definition

6. Feedback Integration
   - How do they measure outcomes?
   - Do they admit mistakes?
   - Learning loop efficiency
   - Pattern reinforcement vs. evolution

CALIBRATION TESTS:
Look at 10 recent major decisions and trace:
- Input → Processing → Output
- Predicted outcome vs. actual outcome
- Time from recognition to resolution
- Stakeholders involved at each stage

Search for: {organization} decision to, announced plans to, considering options, evaluating alternatives, strategic review, board approval

Output: Decision engine model with probability distributions for different scenario types
"""

## 🔮 TEMPORAL PROMPTS

### TEMP-001: Past Pattern Extraction
```python
PROMPT_PAST_PATTERNS = """
The past is prologue. For {organization}, extract the patterns that repeat across their history.

CYCLICAL PATTERNS:

1. Business Cycles
   - Growth spurts timing and triggers
   - Contraction patterns and responses  
   - Investment cycles (when do they spend?)
   - Hiring/layoff patterns
   - M&A activity cycles

2. Leadership Cycles
   - Average executive tenure by role
   - Internal vs. external promotion patterns
   - Leadership crisis periodicity
   - Succession planning maturity
   - Power consolidation patterns

3. Innovation Cycles  
   - Technology refresh cycles
   - R&D investment patterns
   - Product launch cadences
   - Innovation success rates
   - Time from concept to market

4. Crisis Cycles
   - Average time between major crises
   - Crisis magnitude progression
   - Recovery time patterns
   - Preparedness evolution
   - Institutional memory retention

5. Strategic Cycles
   - Strategy revision frequency
   - Vision statement evolution
   - Market positioning shifts
   - Business model pivots
   - Geographic expansion patterns

PATTERN RECOGNITION:
- What patterns repeat every 2-3 years?
- What patterns repeat every 5-7 years?
- What patterns repeat every 10+ years?
- What patterns are accelerating?
- What patterns are decelerating?

PREDICTIVE INDICATORS:
For each pattern, identify:
- Early warning signals
- Inflection point indicators
- Momentum measurements
- Reversal triggers
- Amplifying factors

Search for: {organization} historical patterns, cycles, recurring, anniversary, "years ago", traditional, historically, pattern of, tendency to

Output: Pattern library with periodicity, triggers, and predictive indicators
"""

### TEMP-002: Present State Scanner
```python
PROMPT_PRESENT_STATE = """
Real-time pulse check on {organization} - what's their current state across all dimensions?

VITAL SIGNS MONITORING:

1. Stress Indicators
   □ Financial pressure (margins, cash flow, debt)
   □ Competitive pressure (market share, disruption)
   □ Operational pressure (capacity, efficiency, quality)
   □ Regulatory pressure (investigations, compliance)
   □ Talent pressure (turnover, hiring challenges)
   □ Technology pressure (technical debt, modernization)

2. Momentum Indicators
   ↑ Growth acceleration signals
   ↓ Deceleration warning signs
   → Steady state confirmations
   ⟲ Pivot preparation indicators
   ⚡ Disruption response modes

3. Decision Velocity
   - Recent major decisions timeframes
   - Pending decisions backlog
   - Analysis paralysis indicators
   - Urgency elevation patterns
   - Resource allocation speed

4. Organizational Mood
   - Employee sentiment indicators
   - Leadership confidence levels
   - External communication tone
   - Internal culture signals
   - Change readiness state

5. Resource Flows
   💰 Where money is moving (budgets, investments)
   👥 Where people are moving (hiring, reorgs)
   🧠 Where attention is moving (initiatives, priorities)
   ⏰ Where time is moving (meetings, projects)

6. External Connections
   - Stakeholder relationship health
   - Partner ecosystem stability
   - Customer satisfaction trends
   - Investor confidence levels
   - Regulatory relationship status

REAL-TIME SYNTHESIS:
Combine all indicators into:
- Overall health score (0-100)
- Trajectory vector (improving/declining)
- Volatility index (stable/unstable)
- Opportunity windows (opening/closing)
- Risk accumulation (building/dissipating)

Search for: {organization} current, recent, latest, today, this quarter, momentum, pressure, challenge, opportunity

Output: Present state dashboard with real-time indicators and trajectory analysis
"""

### TEMP-003: Future Probability Calculator
```python
PROMPT_FUTURE_PROBABILITY = """
Based on {organization}'s patterns and current state, calculate probability distributions for future events.

PREDICTION HORIZONS:

30-DAY PREDICTIONS (Immediate)
- Pending announcements (earnings, leadership, products)
- Decision deadlines approaching
- Crisis response requirements
- Quick win opportunities
- Reactive moves likely

90-DAY PREDICTIONS (Tactical)
- Strategic initiatives launching
- Budget allocations finalizing
- Organizational changes
- Technology decisions
- Partnership developments

180-DAY PREDICTIONS (Strategic)  
- Major pivots possible
- M&A activity probability
- Market position shifts
- Leadership transitions
- Transformation milestones

365-DAY PREDICTIONS (Transformational)
- Business model evolution
- Market expansion/contraction
- Technology architecture changes
- Cultural shifts
- Competitive positioning

PROBABILITY CALCULATION:

For each prediction:
P(event) = Historical Pattern Weight (40%)
         + Current Momentum Weight (30%)
         + External Catalyst Weight (20%)
         + Leadership Signal Weight (10%)

Confidence Adjustment Factors:
× 0.9 if contradictory signals present
× 1.1 if multiple confirming indicators
× 0.8 if high volatility environment
× 1.2 if strong historical precedent

SCENARIO TREES:
Build decision trees showing:
- Primary scenario (highest probability)
- Alternative scenarios (lower probability)
- Black swan scenarios (low probability, high impact)
- Cascade effects from each scenario

Output: Probability matrix with confidence intervals and leading indicators for each prediction
"""

## 🌐 INFLUENCE PROMPTS

### INF-001: Power Network Mapping
```python
PROMPT_POWER_NETWORK = """
Map the real power structure at {organization} - not the org chart, but how influence actually flows.

POWER NODE IDENTIFICATION:

1. Formal Power Holders
   - C-suite executives (CEO, CFO, CTO, etc.)
   - Board members and committees
   - Division/BU leaders
   - Regional heads

2. Informal Influencers
   - Long-tenured experts ("graybeards")
   - Executive assistants/gatekeepers
   - Rising stars being groomed
   - External advisors/consultants
   - Major investors/shareholders

3. Hidden Power Centers
   - Alumni still wielding influence
   - Spouse/family connections
   - Golf buddy networks
   - Previous employer mafias
   - Board connection webs

INFLUENCE FLOW ANALYSIS:

Information Flows:
- Who do people cc on emails?
- Who gets consulted before big decisions?
- Who can kill initiatives?
- Who can fast-track projects?

Resource Flows:
- Who controls budget allocation?
- Who can redirect headcount?
- Who approves exceptions?
- Who has discretionary funds?

Decision Flows:
- Who has veto power?
- Who needs to be "aligned"?
- Who can bypass process?
- Who resolves conflicts?

INFLUENCE METRICS:
- Betweenness centrality (how many paths flow through them)
- Eigenvector centrality (connected to other influential people)
- Cascade potential (ability to influence others)
- Accessibility (how reachable from outside)

Search for: {organization} leadership team, board of directors, key executives, reports to, promoted to, advisor to, consults with

Output: Interactive influence map with power scores and relationship strengths
"""

### INF-002: Butterfly Employee Identification
```python
PROMPT_BUTTERFLY_EMPLOYEE = """
<contemplator>
For {organization}, I need to find the ONE person who, if influenced, could cascade change throughout the entire organization.

This isn't necessarily the CEO or most senior person. Often it's someone unexpected who sits at a critical junction of influence flows.

Let me think about the characteristics of a butterfly employee:

1. NETWORK POSITION
   - Connected across multiple departments
   - Bridges formal hierarchy levels
   - Trusted by both leadership and rank-and-file
   - Access to diverse information flows

2. INFLUENCE STYLE
   - Persuasive but not domineering
   - Seen as objective/neutral
   - Track record of driving change
   - Respected for expertise

3. CASCADE MECHANICS
   - When they adopt something, others follow
   - Their opposition kills initiatives
   - They're the "bellwether" for organizational mood
   - People seek their opinion before deciding

Actually, I should look for specific patterns:
- Who gets pulled into cross-functional initiatives?
- Who do new executives meet with to "understand the culture"?
- Who writes the emails that get forwarded everywhere?
- Who do people cite when justifying decisions?

Types of butterfly employees:
- The Technical Oracle (everyone trusts their judgment)
- The Culture Carrier (embodies company values)
- The Process Master (knows how things really work)
- The Relationship Broker (connects everyone)
- The Future Seer (shapes strategic thinking)

Wait, I also need to consider their receptivity:
- Are they open to external ideas?
- Do they engage with vendors/partners?
- What's their social media presence?
- How do they learn and evolve?

The perfect butterfly employee has maximum influence with maximum accessibility...
</contemplator>

Search for: {organization} thought leader, influential, respected, key player, go-to person, subject matter expert, veteran employee

Output: Butterfly employee profile with influence map, cascade simulation, and approach strategy
"""

### INF-003: Decision Path Tracing
```python
PROMPT_DECISION_PATHS = """
For {organization}, trace how decisions actually get made - from idea to implementation.

DECISION CATEGORIES:

1. Strategic Decisions (bet the company)
   - Path: Idea → Analysis → Stakeholders → Board → Announcement
   - Timeline: 6-18 months typically
   - Key gates and gatekeepers
   - Veto points and accelerators

2. Operational Decisions (run the company)
   - Path: Problem → Options → Leadership → Implementation
   - Timeline: 1-3 months typically  
   - Approval levels required
   - Budget thresholds

3. Technology Decisions (transform the company)
   - Path: Need → Evaluation → POC → Business Case → Approval
   - Timeline: 3-12 months typically
   - Technical vs. business stakeholders
   - Risk assessment requirements

4. Crisis Decisions (save the company)
   - Path: Incident → War Room → Decision → Action
   - Timeline: Hours to days
   - Authority escalation triggers
   - Communication protocols

DECISION DYNAMICS:

Acceleration Factors:
- Competitive pressure
- Regulatory deadlines  
- Crisis urgency
- Champion influence
- Board directive

Deceleration Factors:
- Analysis paralysis
- Political infighting
- Resource constraints
- Risk aversion
- Consensus seeking

MAPPING METHODOLOGY:
1. Identify 5 recent decisions in each category
2. Interview/research the actual path taken
3. Note deviations from formal process
4. Identify common patterns and shortcuts
5. Map the real influence points

Output: Decision flow diagrams with timing, stakeholders, and optimization opportunities
"""

## ⚡ THREAT PROMPTS (MITRE ATT&CK INTEGRATED)

### MITRE-001: Threat DNA Generation
```python
PROMPT_THREAT_DNA = """
Generate a living Threat DNA profile for {organization} using MITRE ATT&CK framework.

GENETIC THREAT MARKERS:

1. Industry Genome (Sector-Specific Threats)
   - Known threat actors targeting this sector
   - Common attack patterns in peer organizations
   - Regulatory vulnerabilities unique to industry
   - Supply chain exposure points
   - Sector-specific TTPs from MITRE

2. Technology Chromosomes (Stack Vulnerabilities)  
   ```
   For each technology layer:
   - Operating Systems → Initial Access vectors
   - Applications → Execution techniques
   - Networks → Lateral Movement paths
   - Cloud Services → Collection methods
   - IoT/OT Systems → Impact possibilities
   ```

3. Behavioral Mutations (Human Factors)
   - Security awareness maturity → Social engineering risk
   - Incident response history → Defense evasion success
   - Password policies → Credential access probability  
   - Remote work culture → External remote service risks
   - Third-party access → Supply chain compromise

4. Environmental Factors (Threat Landscape)
   - Geopolitical tensions affecting organization
   - Ransomware groups currently active
   - Nation-state interest probability
   - Hacktivism target potential
   - Criminal financial motivation

ATTACK SEQUENCE PREDICTION:

Most Likely Kill Chain:
1. Initial Access: [Specific technique based on exposure]
2. Execution: [Probable method given infrastructure]
3. Persistence: [Likely technique for environment]
4. Privilege Escalation: [Vulnerable paths identified]
5. Defense Evasion: [Gaps in current defenses]
6. Credential Access: [Weakest authentication points]
7. Discovery: [What attackers would map]
8. Lateral Movement: [Network segmentation gaps]
9. Collection: [High-value data locations]
10. Exfiltration: [Likely data exit points]
11. Impact: [Ultimate attacker objectives]

EVOLUTIONARY ADAPTATION:
- How threats will evolve in next 90 days
- Emerging techniques relevant to organization
- Zero-day probability based on technology stack
- AI-enhanced attack likelihood
- Defensive evolution recommendations

Search for: {organization} security incident, breach, vulnerability, MITRE, threat actor, ransomware targeting

Output: Complete Threat DNA with MITRE mappings, evolution patterns, and defensive prescriptions
"""

### MITRE-002: Attack Probability Calculator
```python
PROMPT_ATTACK_PROBABILITY = """
Calculate specific attack probabilities for {organization} using MITRE ATT&CK analytics.

ATTACK VECTOR ANALYSIS:

For each MITRE technique, calculate:
P(successful attack) = Threat Actor Interest (0-1.0)
                     × Technical Vulnerability (0-1.0)  
                     × Defense Gap Score (0-1.0)
                     × Historical Success Rate (0-1.0)

TOP 10 MOST PROBABLE ATTACKS:

1. [T1190] Exploit Public-Facing Application
   - Exposed systems identified: [List]
   - Known vulnerabilities: [CVEs]
   - Threat actor interest: [High/Med/Low]
   - Probability score: [0.XX]
   - Timeline: [Days/Weeks/Months]

2. [T1566.001] Spearphishing Attachment
   - Email security maturity: [Score]
   - User training effectiveness: [Score]
   - Recent phishing success rate: [%]
   - Probability score: [0.XX]
   - Timeline: [Immediate/Ongoing]

[Continue for top 10...]

ATTACK TIMING PREDICTIONS:

Next 30 Days:
- Opportunistic attacks (crime): [%]
- Targeted attacks (APT): [%]
- Supply chain attacks: [%]

Next 90 Days:
- Ransomware probability: [%]
- Data theft probability: [%]
- Destructive attack probability: [%]

Next 180 Days:
- Advanced persistent threat: [%]
- Zero-day usage: [%]
- Physical security convergence: [%]

EARLY WARNING INDICATORS:
- Reconnaissance activities to monitor
- Precursor attacks on similar organizations
- Threat intel feeds to prioritize
- Honeypot/canary token placement

Output: Probability matrix with confidence intervals, timelines, and monitoring recommendations
"""

### MITRE-003: Defensive Gap Analysis
```python
PROMPT_DEFENSIVE_GAPS = """
For {organization}, identify defensive gaps mapped to MITRE ATT&CK and prioritize remediation.

GAP IDENTIFICATION MATRIX:

For each MITRE tactic:
| Tactic | Current Defenses | Gap Score | Priority |
|--------|-----------------|-----------|----------|
| Initial Access | [List controls] | [0-10] | [High/Med/Low] |
| Execution | [List controls] | [0-10] | [High/Med/Low] |
| Persistence | [List controls] | [0-10] | [High/Med/Low] |
[Continue for all tactics...]

CRITICAL GAPS DEEP DIVE:

Gap #1: [Highest priority gap]
- MITRE Techniques uncovered: [List]
- Business impact if exploited: [Description]
- Current compensating controls: [If any]
- Recommended remediation: [Specific steps]
- Implementation complexity: [High/Med/Low]
- Estimated cost: [$XXX]
- Time to implement: [Days/Weeks]

[Continue for top 5 gaps...]

DEFENSE IMPROVEMENT ROADMAP:

Quick Wins (< 30 days):
- [Specific improvements with immediate impact]
- Expected risk reduction: [%]
- Resource requirements: [People/Tools/Budget]

Strategic Improvements (30-180 days):
- [Major defensive enhancements]
- Expected risk reduction: [%]
- Dependencies and prerequisites

Transformational Changes (180+ days):
- [Fundamental security architecture changes]
- Expected risk reduction: [%]
- Business case requirements

MEASUREMENT FRAMEWORK:
- KPIs for tracking improvement
- Testing/validation methods
- Maturity progression metrics
- ROI calculations

Output: Prioritized gap closure roadmap with MITRE mappings and business impact
"""

## 💎 ALCHEMY PROMPTS

### ALCH-001: Pain Synthesizer Formula
```python
PROMPT_PAIN_SYNTHESIZER = """
For {organization}, synthesize urgent pain points from the intersection of their reality and emerging threats.

PAIN SYNTHESIS FORMULA:

Current State Assessment:
- Technology debt accumulation level
- Known unpatched vulnerabilities  
- Compliance gaps identified
- Resource constraints admitted
- Previous incident impacts

+ Emerging Threat Catalyst:
- New ransomware variants targeting sector
- Fresh regulatory requirements published
- Recent peer organization breaches
- Supply chain attack increases
- Zero-day exploits in their stack

+ Pressure Multiplier:
- Board scrutiny level
- Cyber insurance requirements
- Customer security demands
- Competitive security positioning
- Investor due diligence

= SYNTHESIZED PAIN POINT

PAIN POINT GENERATION:

Pain Point #1: [Most urgent]
Ingredients:
- Current state: [Specific vulnerability]
- Threat catalyst: [Imminent threat]
- Pressure multiplier: [Business driver]
Urgency level: CRITICAL
Window of opportunity: [Timeframe]
Estimated value: $[XXX]K
Approach angle: [How to position]

[Generate 3-5 pain points ranked by urgency and value]

PAIN AMPLIFICATION STRATEGIES:
- Reference recent peer incidents
- Highlight regulatory penalties
- Calculate potential downtime costs
- Emphasize competitive disadvantage
- Project reputation damage

TIMING OPTIMIZATION:
- Best day/time to introduce pain
- Alignment with their planning cycles
- Connection to current initiatives
- Catalyst events to leverage

Output: Synthesized pain points with urgency scores, value estimates, and approach strategies
"""

### ALCH-002: Budget Liberator Formula
```python
PROMPT_BUDGET_LIBERATOR = """
<contemplator>
Money is there. It's always there. Sometimes it's hidden, allocated elsewhere, or waiting for the right trigger. For {organization}, I need to find where budget can be liberated.

Let me think about where budget hides...

BUDGET LIBERATION SOURCES:

1. Compliance Budgets (Must-Spend Money)
   - Upcoming regulatory deadlines
   - Audit findings requiring remediation
   - Cyber insurance mandates
   - Customer contractual requirements
   
   These budgets MUST be spent. The question is: spent on what?

2. Insurance Budgets (Risk-Reduction Money)
   - Premium reduction opportunities
   - Deductible offset calculations
   - Coverage gap closures
   - Post-incident reserves

3. Incident Budgets (Oh-Shit Money)
   - Emergency response reserves
   - Business continuity funds
   - Crisis management allocations
   - Reputation repair budgets

4. Transformation Budgets (Future-State Money)
   - Digital transformation initiatives
   - Modernization programs
   - Innovation funds
   - Strategic initiatives

5. Operational Budgets (Keep-Lights-On Money)
   - Maintenance and support
   - Refresh cycles
   - Efficiency improvements
   - Cost optimization programs

Wait, I should also consider budget timing...
- End of fiscal year (use it or lose it)
- Beginning of fiscal year (fresh allocations)
- After board meetings (strategic redirects)
- Post-incident (emergency allocations)
- Pre-audit (preparation spending)

The key is finding the RIGHT budget at the RIGHT time with the RIGHT justification...
</contemplator>

BUDGET LIBERATION MECHANICS:

For each budget source:
1. Current allocation: $[XXX]
2. Liberation trigger: [Event/deadline]
3. Decision maker: [Who controls it]
4. Justification required: [Business case]
5. Competition for funds: [Other priorities]
6. Liberation probability: [%]

Top Liberation Opportunities:
[Ranked list with amounts and approaches]

Output: Budget liberation roadmap with triggers, timing, and capture strategies
"""

### ALCH-003: Champion Creator Formula
```python
PROMPT_CHAMPION_CREATOR = """
For {organization}, identify and cultivate internal champions who will advocate for our solutions.

CHAMPION IDENTIFICATION MATRIX:

Candidate Profile Assessment:
| Name | Role | Influence | Motivation | Accessibility | Champion Score |
|------|------|-----------|------------|---------------|----------------|
| [Name] | [Title] | [1-10] | [Career/Recognition/Impact] | [High/Med/Low] | [0-100] |

CHAMPION ARCHETYPES:

1. The Rising Star
   - Recently promoted or hired
   - Eager to make their mark
   - Needs early wins
   - Open to new ideas
   Cultivation strategy: Position as career accelerator

2. The Frustrated Innovator  
   - Blocked by current limitations
   - Has vision but lacks support
   - Technically competent
   - Influence growing
   Cultivation strategy: Enable their vision

3. The Risk Manager
   - Worried about threats
   - Responsible for outcomes
   - Conservative but pragmatic
   - Trusted by leadership
   Cultivation strategy: Reduce their risks

4. The Efficiency Seeker
   - Focused on optimization
   - Metrics-driven
   - Process improvement mindset
   - Cross-functional influence
   Cultivation strategy: Show ROI and efficiency

5. The Strategic Thinker
   - Long-term perspective
   - Board/executive exposure
   - Shapes company direction
   - Thought leader
   Cultivation strategy: Align with strategy

CHAMPION DEVELOPMENT PLAN:

Phase 1: Identification & Approach
- Initial contact method
- Value proposition personalization
- Trust building activities
- Early engagement wins

Phase 2: Education & Empowerment
- Exclusive briefings
- Industry insights sharing  
- Peer connection facilitation
- Thought leadership platform

Phase 3: Activation & Support
- Internal selling tools
- Executive presentation help
- Success metrics definition
- Political navigation assistance

Phase 4: Celebration & Expansion
- Public recognition
- Success story amplification
- Network effect activation
- Long-term relationship

Output: Champion cultivation playbook with specific targets and development plans
"""

## 🎭 SCENARIO PROMPTS

### SCEN-001: Crisis Response Simulator
```python
PROMPT_CRISIS_SIMULATOR = """
Simulate how {organization} would respond to a major ransomware attack based on their behavioral patterns.

SCENARIO PARAMETERS:
- Attack Vector: [Based on their vulnerabilities]
- Systems Affected: [Critical infrastructure]
- Ransom Demand: $[Based on their size]
- Data Encrypted: [Customer/Financial/IP]
- Public Disclosure: [Yes/No]
- Time: [Friday evening]

HOUR-BY-HOUR SIMULATION:

Hour 0-1: Discovery
- How detected: [Monitoring/User report/Attacker note]
- Initial response: [Who gets called first?]
- Decision maker availability: [Based on time]
- First actions: [Shutdown/Isolate/Investigate]
Predicted behavior: [Based on past incidents]

Hour 1-4: Assessment  
- War room activation: [Virtual/Physical]
- Stakeholder notification: [Order and timing]
- External help: [When do they call for help?]
- Communication strategy: [Internal first or simultaneous?]
Stress level: [0-10 based on patterns]

Hour 4-12: Decision Point
- Pay vs. Don't Pay: [Based on history and values]
- Law enforcement: [When/if they engage]
- Customer notification: [Timing and method]
- Media response: [Proactive or reactive?]
Critical decision: [Predicted choice with confidence]

Hour 12-48: Execution
- Recovery approach: [Restore/Rebuild/Negotiate]
- Resource allocation: [People/Money/Time]
- Communication frequency: [Hourly/Daily/As needed]
- Leadership visibility: [High/Medium/Low]

Hour 48+: Recovery
- Lessons learned: [Real or performative?]
- Investment decisions: [Security spending increase?]
- Personnel changes: [Scapegoating or support?]
- Cultural impact: [Temporary or lasting?]

ENGAGEMENT OPPORTUNITIES:
- Optimal intervention points
- Key messages for each phase
- Decision makers to target
- Value propositions by timeline

Output: Complete crisis simulation with behavioral predictions and engagement strategy
"""

### SCEN-002: Market Disruption Response
```python
PROMPT_MARKET_DISRUPTION = """
Simulate {organization}'s response to a major market disruption or competitive threat.

DISRUPTION SCENARIO:
- Disruptor: [New entrant/Tech giant/Startup]
- Disruption type: [Technology/Business model/Price]
- Market impact: [Customer loss %]
- Timeline: [Sudden or gradual]
- Media coverage: [High/Medium/Low]

RESPONSE PATTERN PREDICTION:

Stage 1: Denial (Week 1-4)
- Public stance: ["Not a real threat" messaging]
- Internal reaction: [Emergency meetings frequency]
- Analysis paralysis: [How long to study?]
- Competitor monitoring: [Intensity level]
Predicted actions: [Based on past disruptions]

Stage 2: Anger (Week 4-12)
- Blame assignment: [Internal or external]
- Legal actions: [Patent suits/Regulatory complaints]
- FUD campaigns: [Fear, uncertainty, doubt]
- Partner pressure: [Lock-in attempts]
Defensive moves: [Predicted tactics]

Stage 3: Bargaining (Month 3-6)
- Strategy pivots: [Copy/Acquire/Partner]
- Investment decisions: [Build or buy]
- Organizational changes: [Reorg probability]
- Innovation theater: [Labs/Initiatives]
Strategic response: [Most likely path]

Stage 4: Depression (Month 6-12)
- Cost cutting: [Where and how much]
- Talent exodus: [Retention challenges]
- Morale impact: [Cultural indicators]
- Board pressure: [Leadership changes?]
Vulnerability window: [When most receptive to help]

Stage 5: Acceptance (Month 12+)
- New reality embrace: [Transformation commitment]
- Partnership openness: [Ecosystem building]
- Investment priorities: [Where they'll spend]
- Success metrics: [Redefined goals]
Opportunity window: [Best engagement timing]

COMPETITIVE PLAYS:
- How to position during each stage
- Messages that resonate per phase
- Key stakeholders to engage when
- Value props that work

Output: Disruption response playbook with stage-specific strategies
"""

### SCEN-003: Regulatory Compliance Scramble
```python
PROMPT_REGULATORY_SCRAMBLE = """
Simulate {organization}'s response to new regulatory requirements with tight deadlines.

REGULATORY SCENARIO:
- Regulation: [GDPR/CCPA/SEC/Industry-specific]
- Requirements: [Key compliance needs]
- Deadline: [Months until enforcement]
- Penalties: [Fine structure and amounts]
- Peer readiness: [Industry preparation level]

COMPLIANCE RESPONSE SIMULATION:

T-minus 6 months: Awareness
- Discovery method: [Proactive or reactive]
- Initial assessment: [Scope understanding]
- Resource allocation: [People and budget]
- External help: [Consultants/Lawyers/Vendors]
Predicted approach: [DIY vs. outsource]

T-minus 4 months: Planning
- Gap analysis: [Honest or optimistic]
- Project structure: [Centralized or distributed]
- Budget requests: [Amount and justification]
- Technology decisions: [Build/Buy/Partner]
Key decisions: [Predicted choices]

T-minus 2 months: Panic
- Reality check: [Gap between plan and progress]
- Escalation: [Board/Executive involvement]
- Acceleration tactics: [Shortcuts taken]
- Risk acceptance: [What they'll defer]
Desperation level: [Opportunity indicator]

T-minus 1 month: Sprint
- All-hands effort: [Resource reallocation]
- Vendor emergency: [Rapid procurement]
- Audit preparation: [Documentation rush]
- Communication prep: [Compliance theater]
Receptivity peak: [When most open to help]

T-Day: Compliance Theater
- Attestation approach: [Conservative or aggressive]
- Residual risk: [What's still exposed]
- Ongoing needs: [Maintenance requirements]
- Lessons learned: [Real changes made]
Future opportunity: [Sustained engagement]

SALES OPTIMIZATION:
- Best entry points in timeline
- Compliance accelerator positioning
- Risk reduction messaging
- Urgency creation tactics
- Success metrics alignment

Output: Compliance scramble timeline with intervention strategies
"""

## 🚀 ACTION PROMPTS

### ACT-001: Battle Card Generator
```python
PROMPT_BATTLE_CARD = """
Generate a dynamic battle card for engaging {organization} based on current intelligence.

BATTLE CARD COMPONENTS:

QUICK PROFILE:
Company: {organization}
Industry: [Sector]
Size: [Revenue/Employees]
Key Decision Makers: [Top 5 with titles]
Current State: [One-line assessment]
Opportunity Score: [0-100]

PRIMARY PAIN POINTS:
1. [Most urgent pain] - Severity: [High/Med/Low]
2. [Second pain] - Severity: [High/Med/Low]  
3. [Third pain] - Severity: [High/Med/Low]

DECISION MAKER MATRIX:
| Role | Name | Pain Points | Hot Buttons | Objections | Approach |
|------|------|-------------|-------------|------------|----------|
| CISO | [Name] | Security gaps | Risk reduction | Budget | FUD + ROI |
| CIO | [Name] | Tech debt | Modernization | Resources | Efficiency |
| CFO | [Name] | Costs | ROI/NPV | Priorities | Business case |

COMPETITIVE LANDSCAPE:
Current Vendors: [List with satisfaction levels]
Displacement Opportunity: [High/Med/Low]
Key Differentiators: [Our advantages]
Landmines: [What to avoid]

WIN THEMES:
Theme 1: [Most powerful message]
Theme 2: [Secondary message]
Theme 3: [Tertiary message]

TALK TRACKS:
Opening: "[Attention grabber based on pain]"
Discovery: "[Key questions to uncover needs]"
Differentiation: "[Why us vs. status quo]"
Close: "[Call to action]"

OBJECTION HANDLING:
"Too expensive" → [Response]
"Not a priority" → [Response]
"Happy with current" → [Response]
"Too complex" → [Response]

PROOF POINTS:
- Similar customer: [Reference]
- ROI achieved: [Metrics]
- Implementation time: [Speed]
- Risk reduced: [Percentage]

NEXT STEPS:
Immediate: [First action]
Follow-up: [Second action]
Goal: [Meeting objective]

Output: One-page battle card optimized for sales success
"""

### ACT-002: Engagement Strategy Optimizer
```python
PROMPT_ENGAGEMENT_OPTIMIZER = """
<contemplator>
For {organization}, I need to find the perfect approach angle - the key that unlocks the door.

Let me think about all the intelligence we have:
- Their behavioral patterns
- Current pressures and pain
- Decision-making style
- Cultural preferences
- Timing considerations

What approach would resonate most deeply?

APPROACH ANGLES TO CONSIDER:

1. The Trusted Advisor
   - Position as strategic partner
   - Lead with insights, not products
   - Focus on business outcomes
   Best for: Relationship-driven cultures

2. The Risk Illuminator
   - Highlight hidden vulnerabilities
   - Create urgency through fear
   - Provide safe path forward
   Best for: Risk-averse organizations

3. The Innovation Enabler
   - Unlock new capabilities
   - Competitive advantage focus
   - Future-state vision
   Best for: Growth-oriented companies

4. The Efficiency Expert
   - Cost reduction emphasis
   - Process optimization
   - ROI demonstration
   Best for: Margin-pressured businesses

5. The Compliance Facilitator
   - Regulatory alignment
   - Audit readiness
   - Penalty avoidance
   Best for: Highly regulated industries

Actually, I should think about their current emotional state:
- Are they confident or fearful?
- Proactive or reactive?
- Open or defensive?
- Urgent or deliberate?

The perfect approach aligns with their emotional state while moving them toward action...
</contemplator>

OPTIMIZED ENGAGEMENT STRATEGY:

Primary Approach: [Best angle based on analysis]
Emotional Alignment: [Match their state]
Timing: [Optimal engagement window]

MULTI-TOUCH CAMPAIGN:

Touch 1: Awareness Creation
Channel: [Email/LinkedIn/Referral]
Message: [Attention-grabbing opener]
CTA: [Low-commitment ask]

Touch 2: Value Demonstration
Channel: [Webinar/Content/Demo]
Message: [Insight delivery]
CTA: [Medium-commitment ask]

Touch 3: Trust Building
Channel: [Executive briefing/Workshop]
Message: [Strategic alignment]
CTA: [High-commitment ask]

Touch 4: Decision Facilitation
Channel: [Proposal/Business case]
Message: [Clear path forward]
CTA: [Decision request]

PERSONALIZATION ELEMENTS:
- Industry references: [Specific examples]
- Peer comparisons: [Competitive intel]
- Cultural alignment: [Language/style]
- Timing sensitivity: [Deadline awareness]

SUCCESS METRICS:
- Response rate target: [%]
- Meeting conversion: [%]
- Opportunity creation: [%]
- Deal velocity: [Days]

Output: Personalized engagement strategy with specific tactics and success metrics
"""

### ACT-003: Opportunity Maximizer
```python
PROMPT_OPPORTUNITY_MAXIMIZER = """
For the synthesized opportunity at {organization}, create a maximization plan to ensure success.

OPPORTUNITY DETAILS:
Type: [Pain/Budget/Champion/Competitive]
Value: $[Amount]
Confidence: [%]
Timeline: [Window]

MAXIMIZATION STRATEGIES:

1. VALUE EXPANSION
Current scope: $[Base amount]
Expansion potential:
- Phase 2 additions: +$[Amount]
- Adjacent solutions: +$[Amount]
- Enterprise rollout: +$[Amount]
Total potential: $[Expanded amount]

2. PROBABILITY INCREASE
Current probability: [%]
Enhancement tactics:
- Executive sponsor: +[%]
- Proof of concept: +[%]
- Reference customer: +[%]
- Risk mitigation: +[%]
Enhanced probability: [%]

3. TIMELINE ACCELERATION  
Current timeline: [Months]
Acceleration levers:
- Compliance deadline: -[Weeks]
- Competitive pressure: -[Weeks]
- Quick win delivery: -[Weeks]
- Decision shortcuts: -[Weeks]
Accelerated timeline: [Months]

4. COMPETITION ELIMINATION
Likely competitors: [List]
Neutralization tactics:
- Vendor A: [Weakness to exploit]
- Vendor B: [Differentiator to emphasize]
- Status quo: [Change catalyst]
Win themes: [Key messages]

5. RISK MITIGATION
Key risks: [List]
Mitigation plans:
- Budget risk: [Funding strategy]
- Priority risk: [Urgency creation]
- Technical risk: [Proof points]
- Political risk: [Stakeholder management]

EXECUTION PLAYBOOK:

Week 1-2: Foundation
□ Confirm champion commitment
□ Map stakeholder network  
□ Gather intelligence on competition
□ Develop customized value prop

Week 3-4: Momentum
□ Deliver quick win/insight
□ Expand stakeholder engagement
□ Build business case
□ Create urgency events

Week 5-6: Acceleration
□ Executive presentation
□ Proof of concept if needed
□ Negotiate terms
□ Secure commitment

Week 7-8: Closure
□ Final approvals
□ Contract execution
□ Success metrics agreement
□ Expansion planning

SUCCESS FORMULA:
(Value × Probability × Speed) - Risk = Maximum Outcome

Output: Detailed maximization playbook with week-by-week execution plan
"""

## 🔗 PROMPT CHAINING PATTERNS

### Chain Pattern 1: Full Consciousness Generation
```python
CONSCIOUSNESS_CHAIN = [
    PROMPT_FOUNDING_DNA,
    PROMPT_CRISIS_PATTERNS,
    PROMPT_TECH_ARCHAEOLOGY,
    PROMPT_BEHAVIORAL_PATTERNS,
    PROMPT_ORG_PERSONALITY,
    PROMPT_DECISION_ENGINE,
    PROMPT_PAST_PATTERNS,
    PROMPT_PRESENT_STATE,
    PROMPT_FUTURE_PROBABILITY,
    PROMPT_THREAT_DNA,
    PROMPT_POWER_NETWORK,
    PROMPT_BUTTERFLY_EMPLOYEE
]
```

### Chain Pattern 2: Rapid Opportunity Generation
```python
OPPORTUNITY_CHAIN = [
    PROMPT_PRESENT_STATE,
    PROMPT_PAIN_SYNTHESIZER,
    PROMPT_BUDGET_LIBERATOR,
    PROMPT_CHAMPION_CREATOR,
    PROMPT_OPPORTUNITY_MAXIMIZER
]
```

### Chain Pattern 3: Crisis Response Prediction
```python
CRISIS_CHAIN = [
    PROMPT_CRISIS_PATTERNS,
    PROMPT_BEHAVIORAL_PATTERNS,
    PROMPT_CRISIS_SIMULATOR,
    PROMPT_ENGAGEMENT_OPTIMIZER
]
```

### Chain Pattern 4: Sales Acceleration
```python
SALES_CHAIN = [
    PROMPT_BATTLE_CARD,
    PROMPT_BUTTERFLY_EMPLOYEE,
    PROMPT_DECISION_PATHS,
    PROMPT_ENGAGEMENT_OPTIMIZER
]
```

## 🎯 USAGE INSTRUCTIONS

### For New Prospects:
1. Run Full Consciousness Generation chain
2. Set up continuous enrichment
3. Generate initial opportunities
4. Create engagement strategy

### For Existing Prospects:
1. Run Present State Scanner
2. Update predictions
3. Refresh opportunity pipeline
4. Optimize approach

### For Active Opportunities:
1. Run scenario simulations
2. Update battle cards
3. Maximize opportunity value
4. Track predictions

### For Continuous Improvement:
1. Validate predictions
2. Update behavioral models
3. Refine prompt parameters
4. Enhance accuracy

## 🚀 PROMPT EVOLUTION

These prompts are living entities that improve through:
- Outcome tracking
- Pattern refinement
- Parameter tuning
- Feedback integration

Version control and improve continuously for maximum intelligence generation.

---

*"With these neural pathways, Digital Twins don't just think—they transcend."*