//! Wazuh ruleset generated from the severity mapping, so rule levels can never drift from
//! what the other outputs use. `clickfixed alerts wazuh-rules` prints it for a custom
//! mapping; `wazuh/rules/clickfixed_rules.xml` is the default mapping's output (checked
//! by a test).

use crate::severity::SeverityMap;
use std::fmt::Write;

pub const BASE_RULE_ID: u32 = 100800;

fn xml(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

pub fn rules_xml(map: &SeverityMap) -> String {
    let mut s = String::new();
    let json_id = BASE_RULE_ID;
    let own_id = BASE_RULE_ID + 1;
    writeln!(s, "<!--").unwrap();
    writeln!(
        s,
        "  clickfixed Wazuh rules. GENERATED from the [[alerts.severity]] mapping:"
    )
    .unwrap();
    writeln!(
        s,
        "    clickfixed alerts wazuh-rules --config <config.toml> > clickfixed_rules.xml"
    )
    .unwrap();
    writeln!(
        s,
        "  Do not edit levels here; change the mapping and regenerate."
    )
    .unwrap();
    writeln!(s, "  Rule ids {}-{}.", BASE_RULE_ID, BASE_RULE_ID + 99).unwrap();
    writeln!(s, "-->").unwrap();
    writeln!(s, "<group name=\"clickfixed,\">").unwrap();
    writeln!(s).unwrap();
    writeln!(
        s,
        "  <!-- Base: clickfixed events, decoded by the built-in json decoder. -->"
    )
    .unwrap();
    writeln!(s, "  <rule id=\"{json_id}\" level=\"0\">").unwrap();
    writeln!(s, "    <decoded_as>json</decoded_as>").unwrap();
    writeln!(s, "    <field name=\"event.module\">^clickfixed$</field>").unwrap();
    writeln!(s, "    <description>clickfixed event</description>").unwrap();
    writeln!(s, "  </rule>").unwrap();
    writeln!(s).unwrap();
    writeln!(
        s,
        "  <!-- Base: clickfixed events, decoded by decoders/clickfixed_decoders.xml. -->"
    )
    .unwrap();
    writeln!(s, "  <rule id=\"{own_id}\" level=\"0\">").unwrap();
    writeln!(s, "    <decoded_as>clickfixed</decoded_as>").unwrap();
    writeln!(s, "    <description>clickfixed event</description>").unwrap();
    writeln!(s, "  </rule>").unwrap();
    for (i, b) in map.bands().iter().enumerate() {
        let id = BASE_RULE_ID + 10 + i as u32;
        writeln!(s).unwrap();
        writeln!(
            s,
            "  <!-- band \"{}\": verdict {}, score >= {} -->",
            xml(&b.name),
            b.verdict.as_str(),
            b.min_score
        )
        .unwrap();
        writeln!(s, "  <rule id=\"{id}\" level=\"{}\">", b.wazuh_level).unwrap();
        writeln!(s, "    <if_sid>{json_id}, {own_id}</if_sid>").unwrap();
        writeln!(
            s,
            "    <field name=\"clickfixed.severity.name\">^{}$</field>",
            xml(&b.name)
        )
        .unwrap();
        writeln!(
            s,
            "    <description>clickfixed {}: $(event.action) on $(host.name), score $(clickfixed.score)</description>",
            xml(&b.name)
        )
        .unwrap();
        writeln!(s, "    <mitre>").unwrap();
        writeln!(s, "      <id>T1204.004</id>").unwrap();
        writeln!(s, "    </mitre>").unwrap();
        writeln!(
            s,
            "    <group>clickfixed_{},{}</group>",
            xml(&b.name),
            if b.wazuh_level >= 12 { "attack," } else { "" }
        )
        .unwrap();
        writeln!(s, "  </rule>").unwrap();
    }
    writeln!(s).unwrap();
    writeln!(s, "</group>").unwrap();
    s
}
