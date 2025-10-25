# Agent Iteration Strategies for Ghidra Function Documentation

## Executive Summary

| Aspect | Stateful Agent Loop | Adaptive Prompt Enhancement |
|--------|-------------------|---------------------------|
| **Complexity** | High | Medium |
| **Learning Curve** | Steep | Moderate |
| **Cost per Function** | Lower (context reuse) | Medium (prompt grows) |
| **Quality Improvement** | Exponential | Linear |
| **Error Recovery** | Excellent | Good |
| **Scalability** | 100+ functions | 50+ functions |
| **Implementation Time** | 2-3 weeks | 1 week |
| **Best For** | Large batches, similar functions | Medium batches, diverse patterns |

---

## Strategy 1: Stateful Agent Loop with Function Queue

### How It Works

The agent maintains persistent state across function iterations, learning patterns and adapting its approach.

```python
class StatefulGhidraAgent:
    def __init__(self, base_prompt_path):
        self.base_prompt = self.load_prompt(base_prompt_path)
        self.function_queue = []
        self.completed = {}
        self.failed = []
        self.learned_patterns = {
            'structures': {},
            'naming_conventions': {},
            'error_patterns': {}
        }
        self.session_state = {
            'total_processed': 0,
            'success_rate': 0,
            'avg_time_per_function': 0
        }
    
    def process_all_functions(self):
        """Main loop that processes functions with learning."""
        while self.function_queue:
            func = self.function_queue.pop(0)
            
            # Build prompt with learned context
            prompt = self.build_adaptive_prompt(func)
            
            # Process function
            result = self.process_function(func, prompt)
            
            # Learn from result
            if result['success']:
                self.completed[func.name] = result
                self.learn_from_success(result)
            else:
                self.failed.append((func, result['error']))
                self.learn_from_failure(result)
            
            # Update session stats
            self.update_statistics(result)
    
    def build_adaptive_prompt(self, func):
        """Build prompt with learned patterns and insights."""
        prompt = self.base_prompt + "\n\n"
        
        # Add learned structures
        if self.learned_patterns['structures']:
            prompt += "## KNOWN STRUCTURES IN THIS CODEBASE:\n"
            for struct_name, definition in self.learned_patterns['structures'].items():
                prompt += f"- {struct_name}: {definition}\n"
            prompt += "\n"
        
        # Add naming patterns
        if self.learned_patterns['naming_conventions']:
            prompt += "## OBSERVED NAMING PATTERNS:\n"
            for pattern_type, examples in self.learned_patterns['naming_conventions'].items():
                prompt += f"- {pattern_type}: {', '.join(examples[:5])}\n"
            prompt += "\n"
        
        # Add function-specific context
        prompt += f"## TARGET FUNCTION:\n"
        prompt += f"Name: {func.name}\n"
        prompt += f"Address: {func.address}\n"
        prompt += f"XRef Count: {func.xref_count}\n"
        prompt += f"Similar Functions: {self.find_similar_functions(func)}\n"
        
        return prompt
    
    def learn_from_success(self, result):
        """Extract learnings from successful documentation."""
        # Extract structure definitions
        if result['structures_created']:
            for struct in result['structures_created']:
                self.learned_patterns['structures'][struct['name']] = struct['fields']
        
        # Extract naming patterns
        if result['variables_renamed']:
            for var_type, examples in self.categorize_variables(result['variables_renamed']):
                if var_type not in self.learned_patterns['naming_conventions']:
                    self.learned_patterns['naming_conventions'][var_type] = []
                self.learned_patterns['naming_conventions'][var_type].extend(examples)
    
    def learn_from_failure(self, result):
        """Learn what NOT to do."""
        error_type = result['error_type']
        function_name = result['function_name']
        
        self.learned_patterns['error_patterns'][error_type] = {
            'count': self.learned_patterns['error_patterns'].get(error_type, {}).get('count', 0) + 1,
            'last_function': function_name,
            'workaround': self.generate_workaround(result)
        }
```

### Advantages

✅ **Exponential Learning**: Each function improves subsequent ones  
✅ **Pattern Discovery**: Automatically identifies common structures and conventions  
✅ **Context Preservation**: Remembers what worked and what didn't  
✅ **Intelligent Prioritization**: Can reorder queue based on dependencies  
✅ **Self-Correcting**: Learns from failures and adjusts strategy  
✅ **Cost Efficient**: Significant token savings after initial functions  
✅ **Production Ready**: Best for large-scale automation (100+ functions)

### Disadvantages

❌ **Higher Complexity**: Requires sophisticated state management  
❌ **Debugging Difficulty**: Hard to track down why agent made certain decisions  
❌ **Setup Time**: Needs careful initialization and testing  
❌ **Agent Drift**: May develop biases or incorrect assumptions over time  
❌ **Error Propagation**: Bad early decisions can corrupt later learning  

### When to Use

- ✓ Processing 100+ functions in one session
- ✓ Functions follow consistent patterns
- ✓ You have time for setup and validation
- ✓ You want maximum automation and learning

### Implementation Priority

```
Week 1: Basic state tracking and learning extraction
Week 2: Pattern recognition and adaptive prompts
Week 3: Error handling and recovery strategies
```

---

## Strategy 2: Adaptive Prompt Enhancement

### How It Works

After processing each function, extract key insights and inject them into the next prompt. Simpler than stateful agent but still learning-focused.

```powershell
# Simple, stateless approach that enhances prompts iteratively
$basePrompt = Get-Content "OPTIMIZED_FUNCTION_DOCUMENTATION.md" -Raw
$insights = @()
$structuresFound = @{}
$namingPatterns = @{}

foreach ($func in $pendingFunctions) {
    # Build enhanced prompt with previous insights
    $enhancedPrompt = $basePrompt
    
    if ($insights.Count -gt 0) {
        $enhancedPrompt += "`n`n## PREVIOUS FUNCTION INSIGHTS:`n"
        $insights | Select-Object -Last 5 | ForEach-Object {
            $enhancedPrompt += "- $_`n"
        }
    }
    
    if ($structuresFound.Count -gt 0) {
        $enhancedPrompt += "`n## KNOWN STRUCTURES:`n"
        $structuresFound.GetEnumerator() | ForEach-Object {
            $enhancedPrompt += "- $($_.Key): $($_.Value)`n"
        }
    }
    
    if ($namingPatterns.Count -gt 0) {
        $enhancedPrompt += "`n## NAMING PATTERNS OBSERVED:`n"
        $namingPatterns.GetEnumerator() | ForEach-Object {
            $enhancedPrompt += "- $($_.Key): $($_.Value -join ', ')`n"
        }
    }
    
    # Add function target
    $enhancedPrompt += "`n## TARGET FUNCTION:`n$($func.Name) @ $($func.Address)`n"
    
    # Process function
    Write-Host "Processing: $($func.Name)"
    $output = claude -c --dangerously-skip-permissions $enhancedPrompt
    
    # Extract insights from output
    $newInsights = Extract-Insights $output
    $insights += $newInsights
    
    # Extract structures mentioned
    $structures = Extract-Structures $output
    $structures | ForEach-Object {
        $structuresFound[$_.Name] = $_.Fields
    }
    
    # Extract variable naming patterns
    $renames = Extract-VariableRenames $output
    Extract-NamingPatterns $renames | ForEach-Object {
        if (-not $namingPatterns.ContainsKey($_.Type)) {
            $namingPatterns[$_.Type] = @()
        }
        $namingPatterns[$_.Type] += $_.Example
    }
}
```

### Advantages

✅ **Simple Implementation**: Straightforward logic, easy to debug  
✅ **Quick Setup**: Can be implemented in days, not weeks  
✅ **Flexible**: Easy to modify and tune  
✅ **Lower Risk**: Failures don't corrupt system state  
✅ **Good Learning**: Still captures patterns between functions  
✅ **Cost Reasonable**: Moderate token usage  
✅ **Maintenance Easy**: Clear cause-and-effect relationships  

### Disadvantages

❌ **Linear Learning**: Each function only learns from previous N functions  
❌ **Prompt Growth**: Prompt gets longer with each function (token cost increases)  
❌ **No Context Reordering**: Can't adaptively prioritize functions  
❌ **Limited Memory**: Only remembers recent functions  
❌ **Manual Insight Extraction**: Requires parsing agent output for patterns  

### When to Use

- ✓ Processing 20-50 functions per session
- ✓ Quick turnaround needed
- ✓ Pattern extraction is simple
- ✓ You want easy debugging and maintenance

### Implementation Time

```
Day 1-2: Basic extraction functions
Day 3-4: Insight parsing and injection
Day 5: Testing and refinement
```

---

## Detailed Comparison by Scenario

### Scenario A: Processing 150 Similar Functions

**Stateful Agent Loop:**
- Function 1: 45 seconds, learns structure pattern
- Function 2-50: 15-20 seconds each (learns optimization)
- Function 51-150: 8-12 seconds each (highly optimized)
- **Total: ~1.5 hours**
- **Quality: Excellent** (consistent, self-correcting)

**Adaptive Prompt:**
- Function 1-150: 18-25 seconds each (relatively consistent)
- **Total: ~1 hour**
- **Quality: Good** (consistent, but prompt drift)

### Scenario B: Processing 30 Diverse Functions

**Stateful Agent Loop:**
- Setup and tuning: 2-3 hours
- Processing: ~1 hour
- **Total: 3-4 hours**
- **Quality: Excellent**

**Adaptive Prompt:**
- Setup: 30 minutes
- Processing: ~1 hour
- **Total: ~1.5 hours**
- **Quality: Good**
- **WINNER: Adaptive Prompt** (better ROI)

### Scenario C: Production System (Continuous Processing)

**Stateful Agent Loop:**
- ✅ Maintains long-term learning across sessions
- ✅ Can handle function queue management
- ✅ Excellent error recovery and adaptation
- **WINNER: Stateful Agent Loop**

**Adaptive Prompt:**
- ❌ Prompt becomes huge over time (token cost grows)
- ❌ Learning resets per session
- ❌ Not ideal for continuous processing

---

## Hybrid Approach (Recommended)

Combine both strategies for optimal results:

```powershell
# Phase 1: Quick analysis with adaptive prompt (first 30 functions)
# Phase 2: Extract learnings into knowledge base
# Phase 3: Use stateful agent with knowledge base for remaining functions

$phase1Functions = $allFunctions | Select-Object -First 30
$phase2Functions = $allFunctions | Select-Object -Skip 30 -First 20
$phase3Functions = $allFunctions | Select-Object -Skip 50

# Phase 1: Adaptive prompt gathering
Write-Host "Phase 1: Quick documentation pass..."
$knowledgeBase = Process-WithAdaptivePrompts $phase1Functions

# Phase 2: Extract and formalize learnings
Write-Host "Phase 2: Building knowledge base..."
$formalizedKnowledge = Formalize-LearningPatterns $knowledgeBase

# Phase 3: Use stateful agent with formalized knowledge
Write-Host "Phase 3: Intelligent batch processing..."
$agent = New-StatefulAgent -KnowledgeBase $formalizedKnowledge
$finalResults = $agent.ProcessFunctions($phase3Functions)
```

---

## Decision Matrix

Choose based on your constraints:

```
Do you have 100+ similar functions? 
  YES → Stateful Agent Loop
  NO → Continue...

Do you need to complete in < 2 hours?
  YES → Adaptive Prompt
  NO → Continue...

Is this a one-time batch or continuous?
  ONE-TIME → Adaptive Prompt (quicker to implement)
  CONTINUOUS → Stateful Agent Loop (long-term learning)

Do you have existing pattern documentation?
  YES → Stateful Agent Loop (use as bootstrap)
  NO → Adaptive Prompt (discover patterns first)
```

---

## Implementation Recommendations

### For Your Current Setup

Your `function-process.ps1` is currently stateless. Here's the recommendation:

**Phase 1 (Immediate - Week 1):**
Implement **Adaptive Prompt Enhancement**
- Minimal changes to existing script
- Extract insights from Claude output after each function
- Build knowledge base incrementally
- ~1 hour implementation time

**Phase 2 (Optional - Week 3+):**
Migrate to **Stateful Agent Loop** if processing 50+ functions
- Use Phase 1 knowledge base as bootstrap
- Implement proper state management
- Add intelligent queue reordering

---

## Code Examples

### Adaptive Prompt Implementation (PowerShell)

```powershell
function Extract-Documentation-Insights {
    param([string]$claudeOutput)
    
    $insights = @{
        'structures_created' = @()
        'variables_renamed' = @()
        'naming_patterns' = @()
        'key_findings' = @()
    }
    
    # Extract structure definitions
    $structures = [regex]::Matches($claudeOutput, 'structure?\s+(\w+)\s*\{([^}]+)\}')
    foreach ($match in $structures) {
        $insights['structures_created'] += @{
            'name' = $match.Groups[1].Value
            'fields' = $match.Groups[2].Value
        }
    }
    
    # Extract variable renames
    $renames = [regex]::Matches($claudeOutput, '(\w+)\s+→\s+(\w+)')
    foreach ($match in $renames) {
        $insights['variables_renamed'] += @{
            'old' = $match.Groups[1].Value
            'new' = $match.Groups[2].Value
        }
    }
    
    # Extract key findings
    $findings = [regex]::Matches($claudeOutput, '(?:FINDING|KEY INSIGHT|PATTERN):\s+(.+?)(?=\n|$)')
    foreach ($match in $findings) {
        $insights['key_findings'] += $match.Groups[1].Value
    }
    
    return $insights
}

# Usage in main loop
$cumulativeInsights = @()

foreach ($func in $pendingFunctions) {
    $prompt = $basePrompt
    
    # Inject recent insights
    if ($cumulativeInsights.Count -gt 0) {
        $prompt += "`n`n## LEARNED FROM PREVIOUS FUNCTIONS:`n"
        $cumulativeInsights | Select-Object -Last 10 | ForEach-Object {
            $prompt += "- $_`n"
        }
    }
    
    $output = claude -c --dangerously-skip-permissions $prompt
    $newInsights = Extract-Documentation-Insights $output
    $cumulativeInsights += $newInsights.key_findings
}
```

### Stateful Agent Implementation (Python Pseudocode)

```python
class GhidraDocumentationAgent:
    def __init__(self):
        self.memory = {
            'structures': {},
            'naming_rules': {},
            'error_patterns': {},
            'processing_history': []
        }
    
    def process_batch(self, functions):
        for i, func in enumerate(functions):
            print(f"[{i+1}/{len(functions)}] Processing {func.name}...")
            
            # Build context-aware prompt
            prompt = self._build_prompt(func, self.memory)
            
            # Get AI response
            response = call_claude(prompt)
            
            # Learn from response
            self._learn_from_response(func, response)
            
            # Record in history
            self.memory['processing_history'].append({
                'function': func.name,
                'success': response['success'],
                'structures': response.get('structures', []),
                'timestamp': datetime.now()
            })
    
    def _build_prompt(self, func, memory):
        prompt = BASE_PROMPT
        
        # Add learned structures
        if memory['structures']:
            prompt += "\n\n## KNOWN STRUCTURES:\n"
            for name, schema in memory['structures'].items():
                prompt += f"- {name}: {schema}\n"
        
        # Add similar functions from history
        similar = self._find_similar_functions(func)
        if similar:
            prompt += f"\n## SIMILAR FUNCTIONS PROCESSED:\n"
            for sim_func in similar[:3]:
                prompt += f"- {sim_func['function']} (success: {sim_func['success']})\n"
        
        prompt += f"\n## TARGET: {func.name} @ {func.address}\n"
        return prompt
    
    def _find_similar_functions(self, func):
        """Find previously processed functions with similar xref counts."""
        history = self.memory['processing_history']
        return sorted(
            history,
            key=lambda h: abs(h.get('xref_count', 0) - func.xref_count)
        )[:5]
```

---

## Recommendation for Your Project

Given your current setup with `function-process.ps1`:

### **Go with Adaptive Prompt Enhancement** for these reasons:

1. **Your script is already stateless** - easier to enhance incrementally
2. **Your function batch is probably < 50 functions** - adaptive prompt works great at this scale
3. **Quick ROI** - can implement in 1 week
4. **Low risk** - if it doesn't work, reverting is trivial
5. **Good learning still happens** - you'll still see improvements across the batch

### Implementation Steps:

1. Add `Extract-Documentation-Insights` function to your script
2. Maintain `$cumulativeInsights` array
3. Build enhanced prompt before each function
4. Parse Claude output for patterns
5. Test on first 5 functions, verify improvements

Then in 2-3 weeks, if you're happy with results and have 100+ functions remaining, migrate to stateful agent loop.

---

## Next Steps

Would you like me to:
1. Implement Adaptive Prompt Enhancement in your `function-process.ps1`?
2. Create a reference implementation of the Stateful Agent Loop?
3. Build the hybrid approach that uses both strategies?
