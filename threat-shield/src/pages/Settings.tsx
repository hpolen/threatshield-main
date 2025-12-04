import React, { useState, useEffect } from "react";
import { apiService } from "../services/api";

interface ThreatModelSettings {
  preContext: string;
  // New: global "what good looks like" definitions keyed by objective label
  designObjectivesGood: Record<string, string>;
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
// These are just starter text; you can customize them in the UI.
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

const Settings: React.FC = () => {
  const [settings, setSettings] = useState<ThreatModelSettings>({
    preContext: "",
    designObjectivesGood: { ...DEFAULT_DO_GOOD },
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
      // Save settings to settings.json in the home directory
      await apiService.saveSettings(settings);

      // Show success message
      setSaveStatus("Settings saved successfully!");

      // Clear message after 3 seconds
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

  const handleDoGoodChange = (
    label: string,
    value: string
  ) => {
    setSettings((prev) => ({
      ...prev,
      designObjectivesGood: {
        ...prev.designObjectivesGood,
        [label]: value,
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
