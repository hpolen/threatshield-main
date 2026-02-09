import React, { useState, useEffect } from "react";
import { apiService } from "../services/api";

interface CvssBaseScoreThresholds {
  lowMax: number;    // 0.1 – lowMax  => Low
  mediumMax: number; // (lowMax, mediumMax] => Medium
  highMax: number;   // (mediumMax, highMax] => High
  // Anything above highMax up to 10.0 is treated as Critical
}

interface CvssSettings {
  version: string; // e.g. "4.0" or "3.1"
  baseScoreThresholds: CvssBaseScoreThresholds;
  environmentNotes: string;
}

interface ThreatModelSettings {
  preContext: string;
  // Global "what good looks like" definitions keyed by objective label
  designObjectivesGood: Record<string, string>;
  // New: CVSS configuration for risk scoring
  cvssSettings: CvssSettings;
}

// Local list of design objectives for Settings UI.
// These labels should match what we use elsewhere (e.g., DesignObjectives.tsx).
const DESIGN_OBJECTIVES = [
  {
    key: "maintainability",
    label: "Maintainability",
    description:
      "How easy it is to change, test, and operate the system over time.",
  },
  {
    key: "availability",
    label: "Availability",
    description:
      "Resilience to failures, uptime targets, and graceful degradation.",
  },
  {
    key: "scale",
    label: "Scale",
    description:
      "Ability to handle growth in users, data, and transaction volume.",
  },
  {
    key: "secure",
    label: "Secure",
    description: "Protection against threats, misuse, and data compromise.",
  },
  {
    key: "dataIntegrity",
    label: "Data Integrity",
    description:
      "Correctness, consistency, and lineage of data across systems.",
  },
  {
    key: "systemIntegration",
    label: "System Integration",
    description:
      "Quality of interfaces, upstream/downstream dependencies, and coupling.",
  },
];

// Default "what good looks like" definitions.
const DEFAULT_DO_GOOD: Record<string, string> = {
  Maintainability:
    "Services and components are loosely coupled, with clear ownership, automated tests, and deployment pipelines. Changes can be made safely without ripple effects, and operational runbooks are in place.",
  Availability:
    "Critical user journeys meet agreed uptime and SLO targets. The system degrades gracefully on dependency failure, has clear RTO/RPO, and failover or rollback paths are tested regularly.",
  Scale:
    "The system scales predictably with load. Capacity bottlenecks are understood, autoscaling or capacity management is in place, and major traffic events can be handled without emergency rework.",
  Secure:
    "Security controls follow least-privilege and zero-trust principles. Authentication, authorization, encryption in transit/at rest, and secrets management are robust and regularly reviewed.",
  "Data Integrity":
    "Data is accurate, consistent, and traceable across systems. There are controls to prevent loss, duplication, or corruption, and reconciliation or lineage is in place for critical data flows.",
  "System Integration":
    "Interfaces between systems are well-defined, versioned, and resilient. Dependencies are managed via contracts or APIs rather than tight coupling, and upstream/downstream impact is understood.",
};

// Default CVSS configuration (v4.0, base metrics, standard thresholds)
const DEFAULT_CVSS_SETTINGS: CvssSettings = {
  version: "4.0",
  baseScoreThresholds: {
    lowMax: 3.9,    // 0.1–3.9   => Low
    mediumMax: 6.9, // 4.0–6.9   => Medium
    highMax: 8.9,   // 7.0–8.9   => High
    // 9.0–10.0 => Critical (implicit)
  },
  environmentNotes:
    "Assume an internet-connected environment with strong regulatory and customer impact for confidentiality and integrity breaches. Availability is important but not always safety-critical. Adjust this text to reflect your organization's environment and impact profile.",
};

const Settings: React.FC = () => {
  const [settings, setSettings] = useState<ThreatModelSettings>({
    preContext: "",
    designObjectivesGood: { ...DEFAULT_DO_GOOD },
    cvssSettings: { ...DEFAULT_CVSS_SETTINGS },
  });
  const [saveStatus, setSaveStatus] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState(false);

  // Load settings from settings.json on component mount
  useEffect(() => {
    const loadSettings = async () => {
      try {
        setIsLoading(true);
        const response = await apiService.getSettings();
        if (response && response.data) {
          const data = response.data as Partial<ThreatModelSettings>;

          setSettings({
            preContext: data.preContext ?? "",
            designObjectivesGood: {
              // start from defaults so nothing is blank
              ...DEFAULT_DO_GOOD,
              ...(data.designObjectivesGood || {}),
            },
            cvssSettings: {
              ...DEFAULT_CVSS_SETTINGS,
              ...(data.cvssSettings || {}),
              baseScoreThresholds: {
                ...DEFAULT_CVSS_SETTINGS.baseScoreThresholds,
                ...(data.cvssSettings?.baseScoreThresholds || {}),
              },
            },
          });
        }
      } catch (error) {
        console.error("Error loading settings:", error);
      } finally {
        setIsLoading(false);
      }
    };

    loadSettings();
  }, []);

  const handleSaveSettings = async () => {
    try {
      setIsLoading(true);
      await apiService.saveSettings(settings);

      setSaveStatus("Settings saved successfully!");

      setTimeout(() => {
        setSaveStatus(null);
      }, 3000);
    } catch (error) {
      console.error("Error saving settings:", error);
      setSaveStatus("Error saving settings. Please try again.");
      setTimeout(() => {
        setSaveStatus(null);
      }, 3000);
    } finally {
      setIsLoading(false);
    }
  };

  const handlePreContextChange = (
    e: React.ChangeEvent<HTMLTextAreaElement>
  ) => {
    const value = e.target.value;
    setSettings((prev) => ({
      ...prev,
      preContext: value,
    }));
  };

  const handleDoGoodChange = (label: string, value: string) => {
    setSettings((prev) => ({
      ...prev,
      designObjectivesGood: {
        ...prev.designObjectivesGood,
        [label]: value,
      },
    }));
  };

  const handleCvssVersionChange = (
    e: React.ChangeEvent<HTMLSelectElement>
  ) => {
    const value = e.target.value;
    setSettings((prev) => ({
      ...prev,
      cvssSettings: {
        ...prev.cvssSettings,
        version: value,
      },
    }));
  };

  const handleCvssThresholdChange = (
    field: keyof CvssBaseScoreThresholds,
    value: string
  ) => {
    const numeric = parseFloat(value);
    setSettings((prev) => ({
      ...prev,
      cvssSettings: {
        ...prev.cvssSettings,
        baseScoreThresholds: {
          ...prev.cvssSettings.baseScoreThresholds,
          [field]: isNaN(numeric) ? prev.cvssSettings.baseScoreThresholds[field] : numeric,
        },
      },
    }));
  };

  const handleCvssEnvironmentNotesChange = (
    e: React.ChangeEvent<HTMLTextAreaElement>
  ) => {
    const value = e.target.value;
    setSettings((prev) => ({
      ...prev,
      cvssSettings: {
        ...prev.cvssSettings,
        environmentNotes: value,
      },
    }));
  };

  if (isLoading && !saveStatus && !settings.preContext) {
    // Keep the original loading behavior for initial load
    return (
      <div className="flex justify-center items-center h-screen">
        <div className="animate-spin rounded-full h-12 w-12 border-t-2 border-b-2 border-blue-500"></div>
      </div>
    );
  }

  const { cvssSettings } = settings;
  const { baseScoreThresholds } = cvssSettings;

  return (
    <div className="container mx-auto px-4 py-8 max-w-7xl">
      {/* Status Message at the top */}
      {saveStatus && (
        <div
          className={`mb-4 p-4 rounded-md ${
            saveStatus.includes("Error")
              ? "bg-red-100 text-red-700"
              : "bg-green-100 text-green-700"
          }`}
        >
          {saveStatus}
        </div>
      )}

      <div className="bg-white rounded-lg shadow-md p-6">
        <h1 className="text-2xl font-bold text-gray-800 mb-6">
          Threat Modeling Settings
        </h1>

        <div className="space-y-8">
          {/* Pre-Context of the Organisation */}
          <div>
            <h2 className="text-xl font-semibold text-gray-700 mb-4">
              Pre-Context of the Organisation
            </h2>
            <div className="bg-gray-50 p-6 rounded-md border border-gray-200">
              <div className="space-y-4">
                <p className="text-gray-600">
                  This section allows you to document any security mechanisms or
                  controls that are already implemented in your organization.
                  Including this information helps prevent false positives
                  during threat modeling by acknowledging existing security
                  measures.
                </p>

                <div>
                  <label
                    htmlFor="preContext"
                    className="block text-sm font-medium text-gray-700 mb-2"
                  >
                    Security Controls and Mechanisms
                  </label>
                  <textarea
                    id="preContext"
                    name="preContext"
                    rows={4}
                    value={settings.preContext}
                    onChange={handlePreContextChange}
                    className="w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-blue-500 focus:border-blue-500"
                    placeholder="Describe existing security controls, authentication mechanisms, encryption standards, etc."
                  ></textarea>
                </div>
              </div>
            </div>
          </div>

          {/* Global Design Objective Definitions */}
          <div>
            <h2 className="text-xl font-semibold text-gray-700 mb-4">
              Design Objective Definitions – “What Good Looks Like”
            </h2>
            <div className="bg-gray-50 p-6 rounded-md border border-gray-200 space-y-4">
              <p className="text-gray-600 text-sm">
                These definitions describe what “good” looks like for each
                design objective across your organization. They act as global
                defaults and will be applied whenever you run Design Objective
                Alignment, so you don’t have to re-enter them each time.
              </p>

              <div className="space-y-6">
                {DESIGN_OBJECTIVES.map((obj) => {
                  const label = obj.label;
                  const value =
                    settings.designObjectivesGood?.[label] ??
                    DEFAULT_DO_GOOD[label] ??
                    "";

                  return (
                    <div
                      key={obj.key}
                      className="border border-gray-200 rounded-md bg-white p-4"
                    >
                      <div className="flex justify-between items-start gap-3 mb-2">
                        <div>
                          <h3 className="text-sm font-semibold text-gray-800">
                            {label}
                          </h3>
                          <p className="text-xs text-gray-500">
                            {obj.description}
                          </p>
                        </div>
                      </div>
                      <label className="block text-xs font-medium text-gray-700 mb-1">
                        What “good” looks like (global definition)
                      </label>
                      <textarea
                        rows={3}
                        value={value}
                        onChange={(e) =>
                          handleDoGoodChange(label, e.target.value)
                        }
                        className="w-full px-3 py-2 border border-gray-300 rounded-md text-sm shadow-sm focus:outline-none focus:ring-blue-500 focus:border-blue-500"
                        placeholder={`Describe your organizational definition of “good” for ${label.toLowerCase()}.`}
                      ></textarea>
                    </div>
                  );
                })}
              </div>
            </div>
          </div>

          {/* CVSS Risk Scoring Configuration */}
          <div>
            <h2 className="text-xl font-semibold text-gray-700 mb-4">
              CVSS Risk Scoring Configuration
            </h2>
            <div className="bg-gray-50 p-6 rounded-md border border-gray-200 space-y-4">
              <p className="text-gray-600 text-sm">
                Configure how CVSS scoring is applied when you choose CVSS as
                the risk model for an assessment. These settings are passed into
                the CVSS engine so you have a clear, auditable view of how
                scores and severity bands are derived.
              </p>

              {/* Version selection */}
              <div className="space-y-2">
                <label className="block text-sm font-medium text-gray-700">
                  CVSS Version
                </label>
                <select
                  value={cvssSettings.version}
                  onChange={handleCvssVersionChange}
                  className="w-full max-w-xs px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-blue-500 focus:border-blue-500 text-sm"
                >
                  <option value="4.0">CVSS v4.0 (recommended)</option>
                  <option value="3.1">CVSS v3.1</option>
                </select>
                <p className="text-xs text-gray-500">
                  This indicates which CVSS specification the engine should use
                  when interpreting metrics and computing scores. MVP is tuned
                  for v4.0 but you can still document if you are aligning to
                  3.1.
                </p>
              </div>

              {/* Base score thresholds */}
              <div className="space-y-3">
                <label className="block text-sm font-medium text-gray-700">
                  Base Score Severity Thresholds
                </label>
                <p className="text-xs text-gray-500 mb-1">
                  Define how base scores map to qualitative severity for your
                  organization. Defaults follow the common CVSS banding, but you
                  can tighten or relax these ranges if needed.
                </p>

                <div className="grid gap-3 md:grid-cols-3">
                  <div>
                    <label className="block text-xs font-medium text-gray-700 mb-1">
                      Low max score
                    </label>
                    <input
                      type="number"
                      min={0}
                      max={10}
                      step={0.1}
                      value={baseScoreThresholds.lowMax}
                      onChange={(e) =>
                        handleCvssThresholdChange("lowMax", e.target.value)
                      }
                      className="w-full px-3 py-2 border border-gray-300 rounded-md text-sm shadow-sm focus:outline-none focus:ring-blue-500 focus:border-blue-500"
                    />
                    <p className="text-[11px] text-gray-500 mt-1">
                      Scores from 0.1 up to this value are treated as{" "}
                      <span className="font-semibold">Low</span>.
                    </p>
                  </div>

                  <div>
                    <label className="block text-xs font-medium text-gray-700 mb-1">
                      Medium max score
                    </label>
                    <input
                      type="number"
                      min={0}
                      max={10}
                      step={0.1}
                      value={baseScoreThresholds.mediumMax}
                      onChange={(e) =>
                        handleCvssThresholdChange("mediumMax", e.target.value)
                      }
                      className="w-full px-3 py-2 border border-gray-300 rounded-md text-sm shadow-sm focus:outline-none focus:ring-blue-500 focus:border-blue-500"
                    />
                    <p className="text-[11px] text-gray-500 mt-1">
                      Scores {baseScoreThresholds.lowMax.toFixed(1)}–{baseScoreThresholds.mediumMax.toFixed(1)}{" "}
                      are treated as <span className="font-semibold">Medium</span>.
                    </p>
                  </div>

                  <div>
                    <label className="block text-xs font-medium text-gray-700 mb-1">
                      High max score
                    </label>
                    <input
                      type="number"
                      min={0}
                      max={10}
                      step={0.1}
                      value={baseScoreThresholds.highMax}
                      onChange={(e) =>
                        handleCvssThresholdChange("highMax", e.target.value)
                      }
                      className="w-full px-3 py-2 border border-gray-300 rounded-md text-sm shadow-sm focus:outline-none focus:ring-blue-500 focus:border-blue-500"
                    />
                    <p className="text-[11px] text-gray-500 mt-1">
                      Scores {baseScoreThresholds.mediumMax.toFixed(1)}–{baseScoreThresholds.highMax.toFixed(1)}{" "}
                      are treated as <span className="font-semibold">High</span>. Anything above this up to 10.0 is{" "}
                      <span className="font-semibold">Critical</span>.
                    </p>
                  </div>
                </div>
              </div>

              {/* Environment notes */}
              <div className="space-y-2">
                <label className="block text-sm font-medium text-gray-700">
                  Environment & Impact Assumptions
                </label>
                <textarea
                  rows={4}
                  value={cvssSettings.environmentNotes}
                  onChange={handleCvssEnvironmentNotesChange}
                  className="w-full px-3 py-2 border border-gray-300 rounded-md text-sm shadow-sm focus:outline-none focus:ring-blue-500 focus:border-blue-500"
                  placeholder="Describe how you want the scoring logic to think about your environment. For example, which systems are internet-exposed, which data types are most sensitive, and how outages translate into business impact."
                ></textarea>
                <p className="text-xs text-gray-500">
                  This text is provided to the CVSS engine as context so that
                  metric choices (e.g., impact, scope) reflect your
                  organization’s reality rather than a generic internet system.
                </p>
              </div>
            </div>
          </div>

          {/* Save Button */}
          <div className="flex justify-end">
            <button
              onClick={handleSaveSettings}
              disabled={isLoading}
              className="px-6 py-3 bg-[#0052cc] text-white rounded-md hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-2 transition-all duration-200 disabled:opacity-50"
            >
              {isLoading ? "Saving..." : "Save Settings"}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Settings;
