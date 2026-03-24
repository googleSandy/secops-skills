# Testing Your YARA-L Detection Rule Before Going Live

You've saved your rule successfully. Here's the step-by-step workflow to validate it works correctly before enabling it for continuous live detection.

## Step 1: Run Test (Validation Phase)

**Purpose**: Validate that your rule syntax is correct and logic works on historical data without generating any alerts.

**How to do it**:
1. Go to the **Rules Editor**
2. Locate your saved rule
3. Click **Run Test**
4. Select a historical time range that covers the attack patterns you're trying to detect
5. Review the test results

**What to expect**:
- The test will execute your rule logic against historical data
- Results are **NON-PERSISTENT** (they won't be stored or trigger alerts)
- No suppression window is applied during testing
- You'll see which events matched your rule conditions
- Verify that the matches align with your expected detections

**Key Point**: This is a safe validation step. It proves your rule works syntactically and logically, but generates no real alerts yet.

---

## Step 2: Retrohunt (Generate Real Detections)

**Purpose**: Apply your rule to historical data and generate actual detections and alerts you can review.

**How to do it**:
1. Go to the **Rules Dashboard**
2. Find your rule in the list
3. Click **Retrohunt** on your rule
4. Select the historical time range to scan
   - **Critical for multi-event rules**: Ensure the time range is at least as large as your match window size
5. Confirm the retrohunt settings

**What happens**:
- The rule is applied to historical data
- **Real detections and alerts are generated** (and persisted)
- You'll see actual findings that would have triggered during that historical period
- Suppression window WILL be applied if you have one configured

**Important**: Make sure alerting is enabled on your rule before running retrohunt, or no alerts will be generated.

**What to review**:
- Examine the alerts generated
- Check for false positives (alerts on benign activity)
- Check for false negatives (known attacks that didn't trigger)
- Verify alert severity and context are appropriate

---

## Step 3: Verify Rule Behavior

Before enabling live detection, confirm:

1. **Syntax is valid**: Run Test should complete without errors
2. **Logic is correct**: Test results match your expected attack patterns
3. **Retrohunt findings are accurate**: Alerts generated during retrohunt represent real security events, not noise
4. **False positive rate is acceptable**: Review retrohunt results to ensure the rule isn't triggering on legitimate activity
5. **Suppression window works as expected** (if configured): Check that duplicate detections are properly suppressed during retrohunt

---

## Step 4: Enable Live Rule (Go Live)

**Only after successful testing**, enable continuous detection:

1. Go to the **Rules Dashboard**
2. Locate your rule in the list
3. Find the **Live Rule toggle** for your rule
4. **Toggle it ON**

**Critical Reminder**: Saving a rule does NOT automatically enable it. The toggle must be manually activated.

---

## Quick Checklist

- [ ] Rule saved successfully in Rules Editor
- [ ] Run Test completed without errors
- [ ] Test results show expected matches
- [ ] Retrohunt executed on representative historical data
- [ ] Retrohunt alerts are accurate (real security events)
- [ ] False positive rate is acceptable
- [ ] Alerting is enabled before retrohunt (if not, no alerts will generate)
- [ ] Multi-event rule retrohunt time range >= match window size
- [ ] Live Rule toggle is manually enabled in Rules Dashboard
- [ ] Ready for continuous live detection

---

## Common Pitfalls to Avoid

| Pitfall | Impact | Solution |
|---------|--------|----------|
| Enabling rule without testing | High false positive rate, alert fatigue | Always run Test + Retrohunt first |
| Forgetting to toggle Live Rule ON | Rule never detects anything | Manually enable toggle in Rules Dashboard |
| Not enabling alerting before retrohunt | No alerts generated during retrohunt | Enable alerting in rule settings before retrohunt |
| Retrohunt time range too small for multi-event rules | Missed detections | Set retrohunt range >= match window size |
| Confusing Run Test with Retrohunt | No persistent findings to review | Remember: Test = temporary validation, Retrohunt = real detections |
| Run Test not applying suppression window | Underestimating alert volume | Suppression only applies during Retrohunt, not Test |

---

## Summary

Your testing workflow is simple:

1. **Run Test** → Validate syntax and logic (non-persistent)
2. **Retrohunt** → Generate real detections on historical data
3. **Review Results** → Verify accuracy and acceptable false positive rate
4. **Enable Toggle** → Manually turn on Live Rule in Rules Dashboard

Only after these steps should your rule begin continuous detection on incoming events.
